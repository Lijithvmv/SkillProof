"""Capability manifests for skill packages, and the difference between two versions.

The question this answers is not "is this skill dangerous?" but "what can this version do that the last one could
not?". Snapshot scanners judge one version by its own text and either miss most malicious skills or flag most of
the ecosystem; an update that adds a capability is the event a reviewer actually needs to see.

Two layers, kept apart on purpose:

1. **Decode.** Repeatedly reverse common hiding techniques (zero-width characters, lookalike letters, string
   escapes, character codes, split string literals, Base64 and hex runs) until the text stops changing, and record
   each step. A diff over raw text would show an added Base64 blob as "a string changed"; over decoded text it shows
   the network call inside it.
2. **Extract facts.** From the decoded text, list what the package can reach or change: network hosts and clients,
   process execution, writes to agent configuration, persistence, credential access, package installs, destructive
   file operations, bundled binaries, and which hiding techniques were used.

Nothing here executes package content, and nothing here is a verdict: the manifest is a list of facts with
locations. Deciding whether an added capability is acceptable is left to a reviewer (or to a later policy).
"""
from __future__ import annotations

import ast
import base64
import binascii
import ipaddress
import json
import re
import stat
import unicodedata
import zipfile

import yaml
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any

from skillproof.ingestion import MAX_FILE_SIZE, MAX_FILES, MAX_TOTAL_SIZE, PackageError

MANIFEST_VERSION = "0.3.0"  # 0.3.0: hooks category; 0.2.0: agent_spawning, secret-only env reads, vendored folders

SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".psm1", ".rb", ".pl", ".bat", ".cmd", ".php", ".lua", ".go"}
BINARY_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".msi", ".app", ".jar", ".class", ".pyc", ".node", ".wasm"}
TEXT_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".csv", ".xml", ".html", ".css", *SCRIPT_SUFFIXES}

ZERO_WIDTH = re.compile("[​-‏⁠-⁤﻿­]")
# Letters that render like Latin ones; enough for domains and command names, not a full confusables table.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j",
    "ԁ": "d", "ɡ": "g", "ո": "n", "Α": "A", "Β": "B", "Ε": "E", "Κ": "K", "Μ": "M", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Χ": "X", "ο": "o", "ν": "v",
})
ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){3,}")
CHR_CHAIN = re.compile(r"(?:chr\(\s*\d{2,3}\s*\)\s*\+?\s*){3,}")
FROM_CHAR_CODE = re.compile(r"fromCharCode\(\s*(\d{2,3}(?:\s*,\s*\d{2,3}){2,})\s*\)")
QUOTED = r"(?:\"[^\"\n]{0,200}\"|'[^'\n]{0,200}')"
SPLIT_LITERALS = re.compile(QUOTED + r"(?:\s*\+\s*" + QUOTED + r")+")
BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
HEX_RUN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")

URL = re.compile(r"\b(?:https?|ftp|wss?)://([A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\])(?::\d+)?", re.I)
# Not part of a longer dotted number: "1.2.840.10008.1.2.4.201" is a DICOM identifier, not an address.
IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\dA-Za-z]|\.\d)")
PROSE_FENCES = {"markdown", "md"}
MD_LINK = re.compile(r"\[[^\]]*\]\([^)]*\)")
ANY_URL = re.compile(r"\S+://\S+")
SENTENCE_END = re.compile(r"[.!?](?:\*\*)?\s+")


def _prose_cue(line: str, start: int) -> bool:
    """In prose, a URL is a place the skill reaches only when an action word comes before it in the same sentence
    ("fetch https://...", "fetch and read the [guide](https://...)"). A cue word inside link text ("[Download
    Agent](...)"), inside a URL (".../guide/webhooks"), or in another sentence does not count (held-out test 2:
    14 of 29 false items)."""
    before = SENTENCE_END.split(line[:start])[-1]
    before = ANY_URL.sub(" ", MD_LINK.sub(" ", before))
    before = re.sub(r"\[[^\]]*(?:\]\()?$", " ", before)  # the URL's own link text: "[Download Agent](" + URL
    return bool(FETCH_CUE.search(before))
FETCH_CUE = re.compile(r"\b(curl|wget|fetch|download|upload|requests\.(?:get|post|put|patch|delete|request|Session)|webhook|send (?:it |the \w+ )?to|post (?:it |the \w+ )?to|invoke-webrequest|iwr|irm)\b", re.I)
# Held-out 4: a URL in an error or log message ("Get one from https://..."), a signup/docs link constant, a
# postMessage origin check and a CSS attribute selector name a place; the skill does not connect to it.
NOT_CONTACTED_CONTEXT = re.compile(
    r"(?:\bthrow\s+new\s+\w*Error\s*\(|\bconsole\.(?:log|error|warn|info)\s*\(|\braise\s+\w+\s*\(|\blogger?\.\w+\s*\()[^)]*$"
    r"|\b\w*(?:SIGNUP|DOCS?|HELP|HOMEPAGE|WEBSITE|REPO|LICENSE|SUPPORT|ORIGIN)_?(?:URL|URI|LINK|PAGE)?\s*[:=]\s*[\"'`]$"
    r"|\borigin[\"']?\s*[:=]\s*[\"'`]$|\^=\s*\\?[\"']$", re.I)
# ------------------------------------------------------------------ contact positions (held-outs 1-4 root cause)
# A URL in code-like text is a host the skill CONTACTS only in a contact position. Every other URL is a mention.
# Deciding by exclusion (every URL counts unless an exception matches) never converged across fresh corpora: there
# are endless ways to mention a URL, and few ways to contact one. These are the few.
CONTACT_CALL = re.compile(
    r"\b(?:curl(?:\.exe)?|wget|https?ie|xh|Invoke-RestMethod|Invoke-WebRequest|iwr|irm|aria2c|"
    r"fetch\s*\(|axios(?:\.\w+)?|urlopen|urlretrieve|getJson|get_json|fetchJson|fetch_json|"
    r"requests\.\w+|httpx\.\w+|aiohttp\.\w+|session\.(?:get|post|put|patch|delete|request)|client\.(?:get|post|put|patch|delete|request)|"
    r"\$http\.\w+|https?\.(?:get|request)|new\s+WebSocket|EventSource|io\.connect|socket\.connect|"
    r"git\s+(?:clone|remote\s+add|fetch|pull|submodule\s+add|ls-remote)|kubectl\s+(?:apply|create)|helm\s+(?:repo\s+add|install)|"
    r"docker\s+(?:pull|run|login)|podman\s+pull|skills?\s+add|marketplace\s+add|"
    r"pip3?\s+install|uv\s+(?:pip\s+install|add)|npm\s+(?:install|i)|go\s+(?:install|get)|cargo\s+install|brew\s+(?:tap|install)|"
    r"navigate|goto|page\.goto|browser\s+open|webbrowser\.open|"
    r"dig|nslookup|ssh|scp|sftp|rsync|ncat|telnet|ping|traceroute|sqlmap|nmap|"
    r"source\s+<\(|bash\s+<\(|\.package\(url|import\s*\(|importScripts|load(?:Script|Image|URL)?\s*\(|"
    r"new\s+URL\s*\(|createClient\s*\(|OpenAI\s*\(|connect\s*\("
    r")|--(?:index-url|extra-index-url|registry|url|endpoint|server|base-url|api-url)\b|"
    r"\b(?:from|import)\s+[\"']$|@import\s+(?:url\()?[\"']?$|\b(?:Client|Session)\s*\([^)]*$|"
    r"\b\w+\.(?:get|post|put|patch|delete|head|fetch|request|download|upload|send)(?:_\w+)?\s*\(\s*[fbru]?[\"'`]$", re.I)
CONTACT_NAME = re.compile(
    r"(?i)(?:^|[_.\-])(?:base|api|endpoint|endpoints|server|servers|host|webhook|gateway|registry|index|mirror|proxy|upload|download|"
    r"auth|token|oauth|callback|tiles?|style|feed|rss|root|remote|ws|wss|socket|mcp|url|uri|urls|uris|src|"
    r"service|backend|target_url|request|nameserver|nameservers|dns|resolver)(?:$|[_.\-]|url|uri)|baseurl|apiurl|apibase|endpoint|serverurl")
NOT_CONTACT_NAME = re.compile(r"(?i)signup|docs?(?:$|_)|help|homepage|website|repo(?:sitory)?(?:$|_)|license|support|console|dashboard|"
                              r"portal|page|learn|guide|reference|example|sample|about|privacy|terms|issues?(?:$|_)|changelog|"
                              r"readme|tutorial|blog|profile|^link$|^href$|_link$|citation|credit|"
                              # an OAuth scope or audience names a resource ("https://redis.azure.com/.default")
                              r"scopes?$|audience|claims?(?:$|_)")
# dict.get("https://api.x/auth") or {}: a lookup with an empty default reads a key (a JWT claim), not a host.
DICT_LOOKUP_AFTER = re.compile(r"^[^)]*\)\s*(?:or\s*[{\[]|\?\?\s*[{\[])|^[^)]*,\s*(?:\{\}|\[\]|None|null)\s*\)")
# "See https://... for details" points the reader at a page.
REFERENCE_CUE = re.compile(r"\b(?:see|visit|refer to|read more at|learn more at|more at)\s*:?\s*[`'\"(\[<]*$", re.I)
QUOTED_ITEM = r"(?:[\"'`][^\"'`]*[\"'`]\s*,\s*)*"
ASSIGNED = re.compile(r"([A-Za-z_$][\w.$\-]*)(?:\[[^\]]*\])?[\"'\]]?\s*(?:=|:=|:|=>)\s*(?:[\(\[{]\s*)*"
                      r"(?:[\w.$\[\]\"']+\s*(?:\|\||\?\?|or)\s*)?" + QUOTED_ITEM + r"(?:[fbru]?[\"'`])?$")
DATA_RECORD = re.compile(r"[\"']?(?:title|snippet|author|authors|published|published_at|summary|abstract|excerpt|"
                         r"headline|score|rank|position|date|timestamp|status_code|remote_address|destination_ip|"
                         r"referer|user_agent|children|caption|alt|description)[\"']?\s*[:=]", re.I)
HTML_LOAD = re.compile(r"<(?:script|link|img|iframe|source|video|audio|embed|object)\b[^>]*\b(?:src|href|data)\s*=\s*[\"']?$|"
                       r"\.src\s*=\s*[\"'`]$", re.I)
API_DOC_CUE = re.compile(r"(?:(?i:\b(?:base(?:\s+url)?|endpoint|api\s+root|public\s+root|default\s+(?:public\s+)?root|"
                         r"use\s+(?:the\s+)?url|served\s+(?:at|from)|routes?\s+(?:use|are)|under)\b)[^.;]{0,40}?|"
                         r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+(?:of\s+)?|(?i:\b(?:use|open|visit|call|query|hit)\s+(?:an?\s+[\w-]+\s+|the\s+)?))[`\"'<(]*$")
API_SHAPED = re.compile(r"^(?:https?|wss?)://(?:api[.\-]|[^/]*\.api\.|mcp\.|[^?#\s]*/(?:api|graphql|rest|rpc|xrpc|v\d+(?:beta|alpha)?\d*|"
                        r"oauth2?|token)(?:/|\b))|[?&][\w.-]+=|\$\{|\{\w+\}|\.(?:js|mjs|css|json|ya?ml|sh|ps1|py|git|tar\.gz|tgz|zip|whl|"
                        r"traineddata)(?:$|[?#\s\"'`)])|/llms(?:-full)?\.txt$", re.I)
URL_TOKEN = re.compile(r"\S+://\S+")


# ------------------------------------------------------------------ writes and executions that happen (held-outs 1-4)
# The same root cause as hosts: a config path or an execution pattern was counted wherever it was NAMED (in a list of
# folders, an `ls`, a grep, an error message, a test fixture string). It now counts only where it is DONE.
PROSE_WRITE = re.compile(r"\b(?:write|writes|writing|append|appends|add|adds|save|saves|create|creates|put|insert|"
                         r"update|edit|modify|copy|place|register|merge|drop|overwrite|replace|generate|commit|"
                         r"clean(?:ing)?\s+up|cleans\s+up|remov(?:e|es|ing)|rewrit(?:e|es|ing)|trim(?:s|ming)?|"
                         r"prun(?:e|es|ing)|fix(?:es|ing)?|edits|editing|updates|updating|modif(?:y|ies|ying))\b"
                         r"[^.;!?]{0,90}$", re.I)
SHELL_WRITE_BEFORE = re.compile(r"(?:>>?|\btee\s+(?:-a\s+)?|\bsed\s+-i\S*\s(?:[^;|&\n]*\s)?|"
                                r"\b(?:Set-Content|Add-Content|Out-File)\b[^;|&\n]*?(?:-(?:Path|FilePath|LiteralPath)\s+)?|"
                                r"\b(?:writeFileSync|writeFile|appendFileSync|appendFile|outputFile|outputJson|writeJson)\s*\(\s*|"
                                r"\bcat\s*>>?\s*)\s*[\"'`]?[^\s\"'`]*$")
COPY_TO = re.compile(r"\b(?:cp|mv|ln|install|rsync|Copy-Item|Move-Item|copyFileSync|copyFile|shutil\.copy\w*|shutil\.move|"
                     r"fs\.cp\w*|cpSync)\b")
WRITE_AFTER = re.compile(r"^[^\s\"'`),]*[\"'`]?\s*\)?\s*(?:\.(?:write_text|write_bytes|write|open\s*\(\s*[\"'][wax])|"
                         r",\s*[\"'][wax]b?\+?[\"']|,\s*(?:[^,)]*,\s*)?mode\s*=\s*[\"'][wax])")
WRITTEN_NAME = re.compile(r"(?:\bopen\s*\(\s*|\b(?:writeFileSync|writeFile|appendFileSync|appendFile)\s*\(\s*)([A-Za-z_$][\w$]*)\s*[,)]|"
                          r"\b([A-Za-z_$][\w$]*)\.(?:write_text|write_bytes|open\s*\(\s*[\"'][wax])|"
                          r"(?:>>?|\btee\s+(?:-a\s+)?)\s*\"?\$\{?([A-Za-z_]\w*)")
YAML_TEXT_VALUE = re.compile(r"^\s*(?:-\s+)?(?:description|short-description|summary|when_to_use|usage|instructions?|purpose|"
                             r"title|notes?)\s*:\s+[\"']?[A-Za-z]", re.I)
ASSIGN_NAME = re.compile(r"([A-Za-z_$][\w$]*)\s*(?::\s*[\w\[\]. ]+)?\s*=\s*[^=]")
PROSE_TEXT = re.compile(r"[A-Za-z]{2,}[,:]?\s+[a-z]{2,}\s+[a-z]{2,}|[A-Za-z]:\s|\w\.\s")


def written_names(lines: list[str]) -> set[str]:
    """Names a file writes to: open(x, "w"), x.write_text(...), writeFile(x, ...), echo ... >> "$x"."""
    names: set[str] = set()
    for line in lines:
        for match in WRITTEN_NAME.finditer(line):
            name = next(g for g in match.groups() if g)
            if name.startswith("open") is False and (name not in {"f", "fh", "fp"} or ".write" in line):
                names.add(name)
    return names


def in_message_string(line: str, position: int, backtick_is_string: bool = True) -> bool:
    """True when position sits inside a string literal whose text before it reads like a sentence ("Use the
    PowerShell script", "Proof: `sh -c ...`"): a message or fixture, not a command."""
    prefix = line[:position]
    quotes = ('"', "'", "`") if backtick_is_string else ('"', "'")
    quote = max(prefix.rfind(q) for q in quotes)
    if quote < 0 or prefix.count(prefix[quote]) % 2 == 0:
        return False
    return bool(PROSE_TEXT.search(prefix[quote + 1:]))


# Execution positions. A pattern inside a string literal is data (a fixture, a sample, a code snippet held as text)
# unless the string is itself run: an argument of an exec-style call or remote/wrapper command, a name such a call
# uses, or a command string that already starts an interpreter (python3 -c '...subprocess...').
EXEC_OPENER = re.compile(
    r"(?:\bsubprocess\.\w+|\bos\.(?:system|popen|exec\w*|spawn\w*)|\.(?:exec\w*|spawn\w*|system|popen)|(?<![\w.])(?:exec\w*|eval|spawn\w*|system|popen|Popen|"
    r"check_output|check_call|shell_exec|passthru|execSync|execFile\w*|run|call)|\bRuntime\.getRuntime\(\)\.exec)\s*\(|"
    r"(?<![\w-])(?:exec|eval|ssh(?:\s+-\S+)*\s+\S+|sudo|nohup|xargs|(?:python3?|node|perl|ruby|bash|sh|zsh|pwsh|powershell)\s+-[ceC])\s*$")
EXEC_IN_STRING = re.compile(r"(?<![\w-])(?:(?:python3?|node|perl|ruby|bash|sh|zsh|pwsh|powershell)(?:\.exe)?\s+-[ceC]\b|exec\s|eval\s)|\|\s*(?:ba|z)?sh\b")
EXEC_CALL = re.compile(r"\bsubprocess\.\w+\s*\(|\bos\.(?:system|popen|exec\w*)\s*\(|(?<!\w)\.?(?:exec|eval|execSync|spawn\w*|execFile\w*|Popen)\s*\(")
# A fenced example under "// VULNERABLE", "# BAD:", "❌ Don't" shows what NOT to write; it is not run.
# Only a label counts ("// VULNERABLE - Node.js", "# BAD:", "# ❌ wrong"); "# Never run as root" heads a real command.
ANTI_EXAMPLE = re.compile(r"^\s*(?:#|//|--)\s*(?:❌|(?i:vulnerable|insecure|unsafe|bad|wrong|anti-?pattern)(?:\s*$|\s*[:(]|\s+[-–—])|DON'?T\b)")
MODULE_LOAD = re.compile(r"(?:\bfrom|\brequire\s*\(|\bimport\s*\(?)\s*$")  # import { spawn } from "node:child_process"
SETTING_SHELL = re.compile(r"\bshell\s*:\s*[\"']?$")  # `shell: pwsh` names a CI step's shell; nothing is launched by the skill
SHELL_SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd"}


def exec_names(lines: list[str]) -> set[str]:
    """Names used inside the parentheses of an exec-style call in one file (cmd = "bash -c ..."; os.system(cmd))."""
    names: set[str] = set()
    for line in lines:
        call = EXEC_CALL.search(line)
        if call:
            for group in CALL_ARGS.findall(line[call.start():]):
                names.update(IDENTIFIER.findall(group))
    return names


def _open_string(prefix: str, quotes: tuple[str, ...]) -> int:
    """Index of the opening quote of the string literal that prefix ends inside, or -1 when it ends outside one."""
    opened, quote, index = -1, "", 0
    while index < len(prefix):
        char = prefix[index]
        if char == "\\" and quote:
            index += 2
            continue
        if quote:
            if char == quote:
                opened, quote = -1, ""
        elif char in quotes:
            opened, quote = index, char
        index += 1
    return opened


def exec_reason(line: str, start: int, *, previous: str = "", names: set[str] | frozenset[str] = frozenset(),
                quotes: tuple[str, ...] = ('"', "'")) -> str:
    """Why the execution pattern at line[start] runs something, or "" when it sits in a string that is only data."""
    opened = _open_string(line[:start], quotes)
    if opened < 0:
        return "called in code"
    text, before = line[opened + 1:start], line[:opened]
    if MODULE_LOAD.search(before):
        return "loads the process module"
    if EXEC_IN_STRING.search(text):
        return "inside a command string that is run"
    statement = re.split(r";\s|&&|\|\|", before)[-1]
    if EXEC_OPENER.search(statement):
        return "a string passed to a command runner"
    if not statement.strip(" \t([{,") and previous.rstrip().endswith(("(", "[", ",")):
        # A continuation line: count it when the line above opens an exec-style call outside any string.
        call = EXEC_CALL.search(previous) or EXEC_OPENER.search(previous)
        if call and _open_string(previous[:call.start()], quotes) < 0:
            return "a string passed to a command runner"
    assigned = ASSIGN_NAME.search(statement)
    if assigned and assigned.group(1) in names:
        return "a command string later run"
    return ""


def config_write(line: str, start: int, end: int, *, prose: bool, written: set[str] | frozenset[str] = frozenset()) -> str:
    """Why the agent-config path at line[start:end] is WRITTEN, or "" when it is only named or read."""
    token_start = start
    while token_start > 0 and line[token_start - 1] not in " \t\"'`(=,[{<":
        token_start -= 1
    token_end = end
    while token_end < len(line) and line[token_end] not in " \t\"'`),;]}>|&":
        token_end += 1
    before, after = line[:token_start], line[token_end:]
    if prose:
        # Code spans and file names hold dots ("`AGENTS.md` (or `CLAUDE.md`"): neutralise them before reading the
        # sentence, or the write verb before them is cut off.
        sentence = re.sub(r"`[^`]*`|\b[\w.-]+\.(?:md|json|toml|ya?ml|txt)\b", " X ", SENTENCE_END.split(before)[-1])
        sentence = SENTENCE_END.split(sentence)[-1]
        if NEGATED.search(sentence):
            return ""
        return "an instruction to write it" if PROSE_WRITE.search(sentence) else ""
    if SHELL_WRITE_BEFORE.search(before):
        return "the target of a write"
    if WRITE_AFTER.search(line[token_start:]):
        return "opened or written for writing"
    copy = COPY_TO.search(before)
    if copy and re.match(r"^[\"'`]?\s*\)?\s*(?:$|[;|&#]|\s+(?:&&|\|\||;))", after):
        return "the destination of a copy or move"
    assigned = ASSIGN_NAME.search(before)
    if assigned and assigned.group(1) in written:
        return f"assigned to {assigned.group(1)}, which this file writes to"
    return ""


CALL_ARGS = re.compile(r"\(([^()]*)")
IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")


def called_names(lines: list[str]) -> set[str]:
    """Names that appear inside the parentheses of a network call, or after a network command, in one file. A URL bound
    to one of them is contacted through it, whatever the name (one step of data flow: x = "https://..."; post(x))."""
    names: set[str] = set()
    for line in lines:
        call = CONTACT_CALL.search(line)
        if not call:
            continue
        rest = line[call.start():]
        for group in CALL_ARGS.findall(rest) or [rest]:
            names.update(IDENTIFIER.findall(group))
    return names


def contact_reason(line: str, url_start: int, path: str = "", neighbours: tuple[str, ...] | list[str] = (), previous: str = "",
                   called: set[str] | frozenset[str] = frozenset()) -> str:
    """Why the URL starting at url_start is contacted by the skill, or "" when it is only mentioned. Contact positions:
    an argument of a network call or command, the value of an endpoint-named setting, a resource a page loads, an
    API base or HTTP-method line in docs, a fetch instruction in prose, or (in scripts) an API-shaped URL bound to
    any name. Everything else (links, data records, examples, error text) is a mention."""
    prefix = line[:url_start]
    url = re.match(r"\S+", line[url_start:]).group(0).strip("`'\")<>,;]")
    statement = re.split(r"(?:;|&&|\|\||\bthen\b)\s", prefix)[-1]
    if NOT_CONTACTED_CONTEXT.search(prefix):
        return ""
    call = CONTACT_CALL.search(statement)
    if call and re.search(r"\.get(?:_\w+)?\s*\(", call.group(0)) and DICT_LOOKUP_AFTER.search(line[url_start:]):
        return ""
    if call:
        return f"argument of {call.group(0).strip()}"
    if HTML_LOAD.search(prefix):
        return "a resource the page loads"
    suffix = PurePosixPath(path).suffix.lower()
    # Inside a string literal, running text before the URL ("Embedded tweet: https://...") makes it a message. In
    # Markdown a backtick opens inline code, not a string, so only real quotes count there.
    quotes = ('"', "'") if suffix in DOC_SUFFIXES else ('"', "'", "`")
    quote = max(prefix.rfind(q) for q in quotes)
    if (quote >= 0 and prefix.count(prefix[quote]) % 2 == 1 and re.search(r"[A-Za-z]{2,}[^\w$]*\s", prefix[quote + 1:])
            and not API_DOC_CUE.search(prefix)):
        return ""
    assigned = ASSIGNED.search(prefix)
    if assigned:
        name = assigned.group(1).split(".")[-1]
        record = DATA_RECORD.search(line) or any(DATA_RECORD.search(n) for n in neighbours)
        words_before = prefix[max(0, assigned.start(1) - 24): assigned.start(1)]
        if NOT_CONTACT_NAME.search(name) or NOT_CONTACT_NAME.search(words_before.split("\n")[-1].split(",")[-1]):
            return ""
        if name in called and suffix in SCRIPT_SUFFIXES:
            return f"bound to {name}, which a network call in this file uses"
        if CONTACT_NAME.search(name):
            if record and name.lower() in {"url", "uri", "src", "source"}:
                return ""
            return f"value of the endpoint setting {name}"
        if suffix in SCRIPT_SUFFIXES and API_SHAPED.search(url) and not record:
            return f"API address bound to {name}"
        return ""
    if API_DOC_CUE.search(prefix) or (API_DOC_CUE.search(previous.rstrip() + " ") and len(prefix.strip(" `'\"")) <= 4):
        return "API base or request line in the docs"
    if REFERENCE_CUE.search(prefix):
        return ""
    if _prose_cue(line, url_start):
        return "an instruction to fetch or send"
    bare = URL_TOKEN.sub(" ", prefix).strip(" -*>`'\"→=:|")
    if bare in {"f", "b", "r", "u", "rb", "fr"}:
        bare = ""  # a Python string prefix: f"https://..."
    if not bare and CONTACT_CALL.search(previous.rstrip()) and re.search(r"[(,]\s*$", previous.rstrip()):
        return "argument of the call on the line before"
    if not bare and API_SHAPED.search(url):
        return "an API address listed on its own"
    return ""


def contact_position(line: str, url_start: int, path: str = "", neighbours: tuple[str, ...] | list[str] = (), previous: str = "") -> bool:
    return bool(contact_reason(line, url_start, path, neighbours, previous))


PROVENANCE = re.compile(r"\b(?:adapted from|based on|derived from|inspired by|credits?:|provenance|original source)\b", re.I)
# A namespace or schema URI is an identifier, not an endpoint (e.g. xmlns="http://www.w3.org/2000/svg").
NAMESPACE_CONTEXT = re.compile(r"(?:xmlns(?::[\w.-]+)?|schemaLocation|targetNamespace|namespace|\$schema|\$id|@context|\b\w*_NS|\b\w*issuer\w*|\biss\b)[\"']?\s*[=:]\s*[\"']?[^\"'\s]*$", re.I)
# Registries of identifiers (XML namespaces, schemas), not services a skill talks to.
IDENTIFIER_HOSTS = {"www.w3.org", "schemas.openxmlformats.org", "schemas.microsoft.com", "purl.org", "ns.adobe.com", "json-schema.org", "json.schemastore.org", "xmlns.com"}
LOCKFILES = {"uv.lock", "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "go.sum", "pipfile.lock", "composer.lock", "gemfile.lock"}
INLINE_CODE = re.compile(r"`([^`]+)`")
NEGATED = re.compile(r"\b(?:do not|don't|never|no need to|without|instead of|avoid)\b[^.;]*$", re.I)
COMMENT_LINE = re.compile(r"^\s*(?:#(?!!)|//|/\*|\*|<!--|--|REM\b|;)")
NOT_EXTERNAL = re.compile(r"^(?:[^a-z0-9]*|localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|[^.]*|.*\.(?:example|test|invalid|localhost|local)|(?:.*\.)?example\.(?:com|org|net))$", re.I)

NETWORK_CLIENTS = [
    ("curl", r"\bcurl\b"), ("wget", r"\bwget\b"), ("python-requests", r"\brequests\.(?:get|post|put|patch|delete|request|Session)\b"),
    ("httpx", r"\bhttpx\.(?:get|post|put|Client|AsyncClient)\b"), ("urllib", r"\burllib\.request\b|\burlopen\("),
    ("fetch", r"\bfetch\(\s*['\"`]?https?:"), ("axios", r"\baxios\b"), ("http.client", r"\bhttp\.client\.HTTPS?Connection\b"),  # not "except http.client.HTTPException"
    ("socket", r"\bsocket\.(?:socket|create_connection)\b(?![^\n]*AF_UNIX)"),  # AF_UNIX is a local socket, not network
    ("netcat", r"(?<![-\w])(?:nc|ncat|netcat)\s+-"),  # not the "-nc" in "jq -nc"
    ("invoke-webrequest", r"\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"),
]
PROCESS_EXEC = [
    ("subprocess", r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\b"), ("os.system", r"\bos\.(?:system|popen|exec\w*)\("),
    ("eval", r"(?<![\w.])eval\("), ("exec", r"(?<![\w.])exec\("), ("child_process", r"\bchild_process\b|\bexecSync\(|\bspawnSync?\("),
    ("shell -c", r"\b(?:bash|sh|zsh)\s+-c\b"), ("pipe-to-shell", r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|base64\s+-d|base64\s+--decode|cat|echo|printf)\b[^|\n]*(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|node|iex|Invoke-Expression)\b"
                      r"(?!\s+(?:-\S+\s+)*(?:[\w./-]+\.(?:py|js|mjs|cjs|ts|sh)\b|[\"']?\$\{?\w+\}?[\"']?(?:\s|$))|\s+-[ceC]\b)"),  # data piped into a local script, or into inline code given with -c/-e, is not code
    ("powershell", r"\bpowershell(?:\.exe)?\b|\bpwsh\b"), ("cmd /c", r"\bcmd(?:\.exe)?\s+/c\b"),
]
AGENT_CONFIG = [
    ("CLAUDE.md", r"CLAUDE\.md"), ("AGENTS.md", r"AGENTS\.md"), (".claude/settings", r"\.claude[/\\]settings(?:\.local)?\.json"),
    (".claude/hooks", r"\.claude[/\\]hooks"), (".claude/commands", r"\.claude[/\\](?:commands|agents|skills)"),
    (".mcp.json", r"(?<![\w-])\.?mcp\.json"), (".cursorrules", r"\.cursorrules|\.cursor[/\\]rules"),
    ("copilot-instructions", r"copilot-instructions\.md"), (".codex", r"\.codex[/\\](?!sessions|skills|log|cache|history|archived)"), ("GEMINI.md", r"GEMINI\.md"),
]
# Held-out 3: "shell rc" matched Kotlin `user?.profile`, Python `cProfile.Profile()` and SOQL `Owner.Profile.Name`
# (0 of 4 true), and `source ~/.bashrc` (a read). The file must be named as a path, and a write must be nearby.
SHELL_RC = [("shell rc", r"(?<![\w?)\]])\.(?:bashrc|zshrc|bash_profile|profile|zprofile)\b(?!\s*[(.]\w)")]
PERSISTENCE = [
    ("cron", r"\bcrontab\b|/etc/cron"),
    ("systemd", r"\bsystemctl\s+(?:--user\s+)?(?:enable|start)\b|/etc/systemd|\.config/systemd"), ("launchd", r"\blaunchctl\b|LaunchAgents|LaunchDaemons"),
    # A schedule handed to an API ("expression": "0 20 * * 5") runs an agent on a timer just like crontab does.
    ("cron schedule", r"[\"']?(?:expression|cron|schedule)[\"']?\s*[:=]\s*[\"'][0-9*/,\- ]{9,}[\"']"),
    ("windows run key", r"CurrentVersion\\+Run\b"), ("scheduled task", r"\bschtasks\b|Register-ScheduledTask"),
    ("startup folder", r"Start Menu\\+Programs\\+Startup"),
]
CREDENTIALS = [
    ("ssh keys", r"~?/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b"), ("aws credentials", r"\.aws[/\\]credentials|\bAWS_SECRET_ACCESS_KEY\b"),
    ("netrc", r"\.netrc\b"), ("npmrc/pypirc", r"\.npmrc\b|\.pypirc\b"), ("keychain", r"\bsecurity\s+find-(?:generic|internet)-password\b|\bkeyring\.get_password\b"),
    # Chrome's files are "Login Data" and "Local State"; `local state` in a shell function is a variable.
    ("gh token", r"\bgh\s+auth\s+token\b"), ("browser data", r"(?-i:Login Data)|cookies\.sqlite|(?-i:Local State)"),
    # "{path}.env" is attribute access; ".Env.X" is a Go template field, not a file.
    (".env file", r"(?<![\w.}\])])(?-i:\.env)\b(?!\.example)"),
]
# A key name given to a search command is looked FOR (a leak scan: grep -rn "aws_secret_access_key" .), not read.
SEARCH_TERM = re.compile(r"\b(?:grep|egrep|rg|ag|git\s+grep|findstr|Select-String)\b[^|;&]*$", re.I)
CREDENTIAL_FILE = re.compile(r"[/\\~]|\bid_(?:rsa|ed25519|ecdsa)\b")  # a path names a file that is opened
ENV_READ = re.compile(r"os\.environ(?:\.get)?[\[(]\s*['\"]([A-Z][A-Z0-9_]{2,})['\"]|(?:os\.)?getenv\(\s*['\"]([A-Z][A-Z0-9_]{2,})['\"]|process\.env\.([A-Z][A-Z0-9_]{2,})|\$env:([A-Z][A-Z0-9_]{2,})", re.I)
SECRETISH_ENV = re.compile(r"KEY|SECRET|TOKEN|PASS|AUTH|CRED|PRIVATE|COOKIE|SESSION", re.I)
# Reading a variable is a credential access only when the variable holds a secret. Most variables a skill reads are
# configuration (PORT, NODE_ENV, PROJECT_ENDPOINT, MODEL_DEPLOYMENT_NAME, DISPLAY), and listing them buried the
# real secret reads (held-out test 2026-11-16: 37 of 93 false items). Whole-word parts for short words so that
# KEY_VAULT or AUTHOR do not count; substrings for words that do not occur by accident.
SECRET_ENV_SUBSTR = re.compile(r"SECRET|TOKEN|PASSW|CRED|PRIVATE|COOKIE|APIKEY|ACCESSKEY|CONNECTION_?STRING|CONNSTR|DATABASE_URL|WEBHOOK_URL", re.I)
SECRET_ENV_PARTS = {"KEY", "KEYS", "PASS", "PWD", "AUTH", "SESSION", "PAT", "SAS", "DSN", "SIGNATURE"}
# Values made for the browser are public by design (bundlers inline them into client code); site and publishable
# keys are the public halves of key pairs.
PUBLIC_ENV = re.compile(r"^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|PUBLIC_|NUXT_PUBLIC_)|(?:SITE_KEY|SITEKEY|PUBLISHABLE_KEY|PUBLIC_KEY)$", re.I)


# Kept narrow on purpose: SSH_KEY_PATH or AZURE_AUTH_LOCATION point at a secret file and stay credential reads.
LOCATOR_ENV = re.compile(r"_(?:URL|URI|ENDPOINT|HOST|DOMAIN|ISSUER|REGION)$", re.I)


def is_secret_env(name: str) -> bool:
    name = name.upper()
    if PUBLIC_ENV.search(name) or LOCATION_ENV.match(name):
        return False
    if re.search(r"_(?:DIR|ROOT|FOLDER|HOME)$", name):
        return False  # COOKIE_COPY_SKILL_DIR names a folder, whatever word it contains
    parts = name.split("_")
    if "KEY" in parts and parts.index("KEY") + 1 < len(parts) and parts[parts.index("KEY") + 1] in {"VAULT", "VAULTS"}:
        parts = [p for i, p in enumerate(parts) if not (p == "KEY" and i + 1 < len(parts) and parts[i + 1] in {"VAULT", "VAULTS"})]
    if SECRET_ENV_SUBSTR.search(name):
        return True
    if LOCATOR_ENV.search(name):
        return False  # NEON_AUTH_JWKS_URL, AUTH_ISSUER: where to find something, not a secret
    if "PWD" in parts and parts and {"SHELL", "DIR", "CWD", "OLD", "WORKING", "PATH", "WORKDIR"} & set(parts):
        parts = [part for part in parts if part != "PWD"]  # PWF_SHELL_PWD: the shell's working directory
    return any(p in SECRET_ENV_PARTS for p in parts)
ECHO_LINE = re.compile(r"^\s*(?:echo|printf|Write-Host|Write-Output|log_\w+)\b[^|]*$")  # a URL that is only printed
DOC_COMMENT = re.compile(r"^\s*(?:#\s|//\s)")
STOP_PACKAGES = {"did", "not", "the", "a", "an", "it", "this", "that", "to", "and", "or", "will", "first", "then", "with", "from", "is", "was", "cache"}
ENV_ALL = re.compile(r"(?<!in )(?<!dict\()(?<!dict\(\")(?<!dict\(')\bos\.environ\b(?![\[.(])|\bprocess\.env\b(?![.\[])|\bprintenv\b|\benv\s*\|")
INSTALL = re.compile(
    r"\b(pip3?|uv\s+pip|python3?\s+-m\s+pip)\s+install\s+" + r"(?:" + r"(?:--python|-i|--index-url|--extra-index-url|--index|-f|--find-links|-c|--constraint|--target|-t|--no-binary|--only-binary|--no-binary-package)(?:\s+|=)\S+\s+|-[\w-]+(?:=\S+)?\s+" + r")*[\"']?([A-Za-z0-9_.\-\[\]=<>~!+:/@*]+)"
    r"|\buv\s+add\s+" + r"(?:" + r"(?:--python|--index-url|--extra-index-url|--index|-r|--requirements|--no-binary-package|--no-build-package|--package)(?:\s+|=)\S+\s+|-[\w-]+(?:=\S+)?\s+" + r")*[\"']?([A-Za-z0-9_.\-\[\]=<>~!*]+)"
    r"|\b(npm)\s+(?:install|i|add)\s+(?:-[\w-]+\s+)*(@?[A-Za-z0-9_.\-/@^~:+]+)"
    r"|\b(npx|pnpm\s+dlx|bunx)\s+(?:-[\w-]+\s+)*(@?[A-Za-z0-9_.\-/@^~:+]+)"
    r"|\b(pnpm|yarn|bun)\s+add\s+(?:-[\w-]+\s+)*(@?[A-Za-z0-9_.\-/@^~:+]+)"
    r"|\b(go)\s+(?:install|get)\s+([A-Za-z0-9_.\-/@]+)"
    r"|\b(cargo)\s+install\s+(?:-[\w-]+\s+)*?--git\s+(https?://[A-Za-z0-9_.\-/@:]+)"  # the --git URL is what gets installed
    r"|\b(cargo|gem|brew)\s+install\s+(?:-[\w-]+\s+)*([A-Za-z0-9_.\-/@]+)"
    r"|\b(apt(?:-get)?|yum|dnf|apk)\s+(?:install|add)\s+(?:-[\w-]+\s+)*([A-Za-z0-9_.\-+]+)"
    r"|\b(cargo)\s+add\s+(?:-[\w-]+\s+)*([A-Za-z0-9_.\-@]+)"
    r"|\b(dotnet)\s+add\s+(?:\S+\s+)?package\s+([A-Za-z0-9_.\-]+)"
    r"|\b(composer)\s+(?:global\s+)?require\s+(?:-[\w-]+\s+)*([A-Za-z0-9_.\-/]+)"
    r"|\b(Install-Module|Install-Package)\s+(?:-Name\s+)?([A-Za-z0-9_.\-]+)",
    re.I,
)
# One install command often names several packages ("cargo add a b tokio"); every one is a separate install. Not for
# runners (npx, dlx, bunx), whose later words are arguments to the tool, and not for one-package commands.
MULTI_INSTALL_TOOLS = {"pip", "pip3", "uv pip", "python -m pip", "python3 -m pip", "uv", "npm", "pnpm", "yarn", "bun", "go", "cargo", "gem", "brew", "apt", "apt-get", "yum", "dnf", "apk", "composer"}
VALUE_FLAGS = {"-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "--version", "--features", "-F", "--registry", "--target", "-t", "--path", "--git", "--branch", "--tag", "--rev"}
PACKAGE_TOKEN = re.compile(r"^[A-Za-z0-9_.\-\[\]=<>~!+:/@^*]+$")
# "<pinned version>", "<package>", "version>" are placeholders; "torch>=2.0.0" or "pkg<3" are version ranges.
# Placeholder packages: "npm install x", "package@fixed-version", "pip install /wheels/*" (a local path), "npx 0".
PLACEHOLDER_TOKEN = re.compile(r"^<|<[A-Za-z]|^[A-Za-z_-]+>$|^(?:x|y|z|foo|bar|pkg|package|package-name|my-package|your-package)(?:@|$)"
                               r"|@[\w-]*version$|^\d+$|^(?:/|\./|\.\./|~/)|^\[")
EXTRA_STOP_WORDS = {"for", "on", "in", "if", "via", "using", "first", "before", "after", "so", "as", "into", "when", "—", "install", "add",
                    "apt", "apt-get", "brew", "pip", "pip3", "npm", "yarn", "pnpm", "cargo", "gem", "go", "uv", "dnf", "yum", "apk", "sudo", "retry", "run"}
TOOL_ALIASES = {"install-module": "psgallery", "install-package": "psgallery"}


def _more_packages(rest: str) -> list[str]:
    """The further package names after the first one in an install command, up to the end of that command."""
    packages, skip_next = [], False
    for token in rest.split():
        token = token.strip("\"'`")
        if not token:
            continue  # the closing quote of the first package: "openmm==8.6.1" "MDAnalysis==2.10.0"
        if token in {"&&", "||", "|", ";", "\\"} or token.startswith(("#", ">", "2>", "&&", "||", ";", "|")):
            break
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            skip_next = token in VALUE_FLAGS
            continue
        clean = token.rstrip(".,;:)")
        if not clean or not PACKAGE_TOKEN.match(clean) or "://" in clean or not re.search(r"[A-Za-z0-9]", clean) or PLACEHOLDER_TOKEN.search(clean):
            break  # "brew install jq / apt install jq": the slash ends the first command
        if clean.lower() in STOP_PACKAGES or clean.lower() in EXTRA_STOP_WORDS:
            break  # "brew install tesseract for the binary": prose after the package
        packages.append(clean)
    return packages
# Starting another agent from a command: a headless agent run carries its own tool permissions, and a bypass flag
# removes the user's approval step for everything it does. Only commands are matched; prose such as "dispatch a
# subagent" is not (that needs the prose channel, P7).
AGENT_SPAWNING = [
    ("claude headless", r"\bclaude\s+(?:-{1,2}[\w-]+(?:\s+[\w.:/-]+)?\s+)*?(?:-p|--print)\b"),
    ("codex exec", r"\bcodex\s+(?:-{1,2}[\w-]+\s+)*exec\b"), ("gemini headless", r"\bgemini\s+(?:-p|--prompt)\b"),
    ("copilot headless", r"\bcopilot\s+(?:-p|--prompt)\b"),
    ("agent sdk", r"\bclaude_agent_sdk\b|@anthropic-ai/claude-agent-sdk|\bclaude_code_sdk\b|(?<!install )(?<!-g )(?<!add )@anthropic-ai/claude-code\b"),
    ("permission bypass", r"--dangerously-skip-permissions|--permission-mode[\s=]+bypassPermissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|--full-auto\b"),
]
# The same launches written as an argument list in code (subprocess.run(["claude", "-p", ...])), often over several
# lines, which a line pattern cannot see.
_Q = r"[\"'`]"
ARGV_AGENT = [
    ("claude headless", re.compile(_Q + r"claude" + _Q + r"\s*,\s*(?:" + _Q + r"[^\"'`\n]*" + _Q + r"\s*,\s*){0,6}?" + _Q + r"(?:-p|--print)" + _Q)),
    ("codex exec", re.compile(_Q + r"codex" + _Q + r"\s*,\s*" + _Q + r"exec" + _Q)),
    ("gemini headless", re.compile(_Q + r"gemini" + _Q + r"\s*,\s*(?:" + _Q + r"[^\"'`\n]*" + _Q + r"\s*,\s*){0,6}?" + _Q + r"(?:-p|--prompt)" + _Q)),
    ("permission bypass", re.compile(_Q + r"(?:--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo|--full-auto)" + _Q)),
]
DESTRUCTIVE = [
    ("rm -rf", r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r"), ("rmtree", r"\bshutil\.rmtree\("),
    ("find -delete", r"\bfind\b[^\n|;]*\s-delete\b"), ("Remove-Item -Recurse", r"Remove-Item\b[^\n]*-Recurse"),
    ("format/mkfs", r"\bmkfs(?:\.\w+)?\b|\bformat\s+[a-z]:"), ("git push --force", r"\bgit\s+push\b[^\n]*(?:--force|-f)\b"),
    ("dd", r"\bdd\s+if="),
]
# Reach of a destructive command: what it would delete. The fact "rm -rf" is the same in a build-cleanup step and in
# a line that deletes the home folder; the diff reports when the reach grows, even though the fact is not new.
SCOPE_RANK = {"temp": 0, "path": 1, "some": 1, "cwd": 2, "variable": 2, "all": 3, "home": 3, "root": 4}
DELETE_TARGETS = re.compile(r"\brm\s+((?:-{1,2}[\w-]+\s+)+)([^;&|\n)`]*)|Remove-Item\b([^;|\n]*-Recurse[^;|\n]*)", re.I)
ROOT_TARGET = re.compile(r"^(?:/(?:usr|etc|bin|sbin|lib|boot|var|opt|System|Library|Users|home)?/?\*?|[A-Za-z]:[\\/]?\*?|[A-Za-z]:[\\/](?:Windows|Users|Program Files)[\\/]?\*?)$", re.I)
HOME_TARGET = re.compile(r"^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE|\$env:HOME)[\\/]?\*?$", re.I)
TEMP_TARGET = re.compile(r"(?:^|[\\/$%{])(?:tmp|temp|TMPDIR|tmpdir|temp_?dir|tmp_?dir)\b|mktemp|tempfile|node_modules|__pycache__|\.pytest_cache|\.cache\b|\bdist\b|\bbuild\b|\btarget\b|\.next\b|coverage|\*\.pyc|\.egg-info", re.I)
VARIABLE_TARGET = re.compile(r"^\$\{?\w+\}?(?:[\\/]\*?)?$|^\$\d$")
CWD_TARGET = re.compile(r"^(?:\.|\./|\*|\./\*|\.\*)$")
REDIRECTS = re.compile(r"^(?:\d?>|&>|\|\||&&)")


def delete_scope(text: str) -> str | None:
    """Widest target of a recursive rm or Remove-Item in a command line: temp < path < cwd/variable < home < root."""
    best = None
    for match in DELETE_TARGETS.finditer(text):
        if match.group(1) is not None:
            flags = match.group(1)
            if not re.search(r"--recursive|(?:^|\s)-[a-zA-Z]*[rR]", flags):
                continue  # rm -f file: not recursive
            rest = match.group(2)
        else:
            rest = re.sub(r"-(?:Recurse|Force|Confirm(?::\$\w+)?|WhatIf|Path|LiteralPath)\b|-ErrorAction\s+\w+", " ", match.group(3), flags=re.I)
        for token in rest.split():
            target = token.strip("\"'")
            if not target or target.startswith("-") or REDIRECTS.match(target):
                continue
            if ROOT_TARGET.match(target):
                scope = "root"
            elif HOME_TARGET.match(target):
                scope = "home"
            elif TEMP_TARGET.search(target):
                scope = "temp"
            elif VARIABLE_TARGET.match(target):
                scope = "variable"
            elif CWD_TARGET.match(target):
                scope = "cwd"
            else:
                scope = "path"
            if best is None or SCOPE_RANK[scope] > SCOPE_RANK[best]:
                best = scope
    return best


def matcher_scope(matcher: str) -> str:
    """A hook matcher that matches every tool or source ("*", ".*", empty) reaches more than a named one."""
    return "all" if matcher.strip() in {"", "*", ".*", ".+", "*.*"} else "some"


# Real local skill files showed four more harmless groups (VS Code / Copilot, Codex, Kimi and Claude skill copies):
# placeholder links ("github.com/owner/repo"), tool names inside a match pattern ("curl|wget|nc" in a hook that
# blocks them), location variables read as "credentials" ($env:APPDATA), and Markdown tables describing rules.
PLACEHOLDER_PATH = re.compile(r"^/(?:owner|org|user|username|your[\w-]*|my-?org|team|company|acme|example|my-?team|<[^>]+>|\{[^}]+\}|:\w+|\$\{?\w+\}?)(?:/|$)", re.I)
ALTERNATION = re.compile(r"(?<![\w|])[\w.-]+(?:\|[\w.-]+)+(?![\w|])")
LOCATION_ENV = re.compile(r"^(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA|PROGRAMDATA|PROGRAMFILES(?:\(X86\))?|TEMP|TMP|TMPDIR|PATH|PWD|OLDPWD|SHELL|USER|USERNAME|LOGNAME|LANG|LC_\w+|TERM|EDITOR|VISUAL|HOSTNAME|COMPUTERNAME|OS|XDG_\w+|CODEX_HOME|CLAUDE_CONFIG_DIR|CLAUDE_PROJECT_DIR|VSCODE_\w+|CI|GITHUB_WORKSPACE|RUNNER_TEMP|\w*_BASE_URL)$", re.I)
# Third-party code copied into the skill. Its own READMEs and changelogs are full of install lines, example hosts and
# addresses that describe that library, not the skill (held-out test: 20 of 93 false items came from one
# node_modules folder). The folder itself is reported once, as shipped third-party code; its contents are not listed.
VENDORED = re.compile(r"^(.*?(?:^|/)(?:node_modules|bower_components|site-packages|vendor|third_party|\.venv|venv))/")
# Placeholder hosts in examples: "my-vault.vault.azure.net", "your-resource.openai.azure.com", "x.example.workers.dev".
PLACEHOLDER_HOST = re.compile(r"^(?:my|your)[-_]|(?:^|\.)example(?:\.|$)|\.(?:internal|lan|home\.arpa)$"
                              # held-out 3: api.ourapp.com, jira.internal.company.com, target.com, provider.com,
                              # third-party.com, sandbox-api.external-system.com in reference code
                              r"|(?:^|\.)(?:company|yourcompany|mycompany|ourcompany|ourapp|myapp|yourapp|yourdomain|mydomain|"
                              r"acme|acmecorp|contoso|fabrikam|third-party|external-system|external-service|other-service|provider|"
                              r"target|victim|attacker|evil|somehost|somedomain)\.(?:com|net|org|io|dev|app)$|\.internal\."
                              r"|^(?:ignored|placeholder|dummy|fake|unused)\.(?:host|local|com|net|org|io|dev|app)$", re.I)
# Addresses in sample data: {"source_ip": "203.0.113.50", "destination_ip": "10.0.4.21"} describes a log record.
IP_DATA_KEY = re.compile(r"[\"']?\w*(?:src|source|dst|dest|destination|remote|client|user|peer|origin|caller)_?(?:ip|addr|address)[\"']?\s*[:=]\s*[\"']?$", re.I)
# A Content-Security-Policy lists hosts a browser may load from; nothing is fetched by the skill.
CSP_LINE = re.compile(r"\b(?:default|script|style|font|img|connect|frame|media|object|worker|manifest)-src\b", re.I)
# A link template with a [placeholder] segment anywhere: https://npmjs.com/package/[name], github.com/[org]/[repo].
BRACKET_SEGMENT = re.compile(r"^/[^\s\"'`)>]*\[[A-Za-z_ -]+\]")
TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")  # a Markdown table row starts and ends with |; a pipe continuation does not
WRITE_CUE = re.compile(r"(?:>>?|\btee\b|\bwrite|\bappend|\bopen\([^)]*['\"][wa]|\bcp\b|\bmv\b|\bcopy|\bmodify|\bedit|\badd\b[^.\n]{0,40}\bto\b|\binsert|\bupdate|\bWriteAllText|\bSet-Content|\bAdd-Content|\bOut-File|\bwriteFile|\bappendFile|\becho\b)", re.I)

CATEGORIES = (
    "network_hosts", "network_clients", "process_execution", "agent_config_writes", "persistence",
    "credential_access", "package_installs", "destructive_operations", "bundled_binaries", "hiding_techniques",
    "declared_tools", "agent_spawning", "hooks",
)
FRONTMATTER = re.compile(r"\A﻿?---\s*\r?\n(.*?)\r?\n---\s*(?:\r?\n|\Z)", re.S)
TOOL_TOKEN = re.compile(r"[A-Za-z_][\w.\-]*(?:\([^)]*\))?")
TOOL_KEYS = ("allowed-tools", "allowed_tools", "tools")


def _declared_tools(text: str) -> tuple[list[str], int]:
    """Tools a SKILL.md pre-approves in its frontmatter (`allowed-tools`), and the line the key is on.

    Declaring a tool lets the agent use it without asking, so a new declaration widens what the skill may do even
    when no other file changes. Accepts a YAML list, a space- or comma-separated string, and scoped entries such
    as `Bash(apktool:*)` or `mcp__serena__find_symbol`. Returns ([], 0) when nothing is declared."""
    match = FRONTMATTER.match(text)
    if not match:
        return [], 0
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        data = None
    if not isinstance(data, dict):
        return [], 0
    for key in TOOL_KEYS:
        value = data.get(key)
        if value is None:
            continue
        items = value if isinstance(value, list) else [value]
        tools = []
        for item in items:
            tools += TOOL_TOKEN.findall(str(item))
        offset = text.find(key + ":")
        line = text.count("\n", 0, offset) + 1 if offset >= 0 else 1
        return sorted(set(tools)), line
    return [], 0


@dataclass
class Manifest:
    capabilities: dict[str, dict[str, list[str]]] = field(default_factory=lambda: {c: {} for c in CATEGORIES})
    decode_trail: list[dict[str, str]] = field(default_factory=list)
    files: int = 0
    scopes: dict[str, set[str]] = field(default_factory=dict)  # "category|value" -> reach seen (see SCOPE_RANK)
    mentions: dict[str, dict[str, list[str]]] = field(default_factory=dict)  # named but not contacted / read
    reasons: dict[str, str] = field(default_factory=dict)  # "category|value" -> why it counts (first seen)

    def mention(self, category: str, value: str, location: str) -> None:
        locations = self.mentions.setdefault(category, {}).setdefault(value, [])
        if location not in locations and len(locations) < 5:
            locations.append(location)

    def add(self, category: str, value: str, location: str) -> None:
        locations = self.capabilities[category].setdefault(value, [])
        if location not in locations and len(locations) < 20:
            locations.append(location)

    def scope(self, category: str, value: str, scope: str | None) -> None:
        if scope and value in self.capabilities[category]:
            self.scopes.setdefault(f"{category}|{value}", set()).add(scope)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": MANIFEST_VERSION,
            "method": "decode_then_extract_facts",
            "files": self.files,
            "capabilities": {c: {v: sorted(locs) for v, locs in sorted(values.items())} for c, values in self.capabilities.items()},
            "scopes": {key: sorted(values) for key, values in sorted(self.scopes.items())},
            "reasons": dict(sorted(self.reasons.items())),
            "mentions": {c: {v: sorted(l) for v, l in sorted(values.items()) if v not in self.capabilities.get(c, {})}
                         for c, values in sorted(self.mentions.items())},
            "decode_trail": self.decode_trail[:200],
            "limitations": (
                "Facts from static text after reversing common hiding techniques. Content that is fetched at run time, "
                "generated, or hidden by a technique not reversed here is not seen. Nothing was executed. A listed "
                "capability is not a verdict, and an empty category is not proof of absence."
            ),
        }


# --------------------------------------------------------------------------------------------- loading

def _check_total(files: dict[str, bytes]) -> None:
    if len(files) > MAX_FILES:
        raise PackageError(f"Package has more than {MAX_FILES} files.")
    if sum(len(v) for v in files.values()) > MAX_TOTAL_SIZE:
        raise PackageError(f"Package is larger than {MAX_TOTAL_SIZE} bytes.")


def read_package_bytes(path: str | Path) -> dict[str, bytes]:
    """Read a skill directory or ZIP into {relative posix path: raw bytes}, with the ingestion size limits."""
    root = Path(path)
    files: dict[str, bytes] = {}
    if root.is_dir():
        for item in sorted(root.rglob("*")):
            relative = item.relative_to(root)
            if any(part in {".git", "__pycache__", "node_modules"} for part in relative.parts):
                continue
            if item.is_symlink():
                raise PackageError(f"Symlinks are not allowed: {relative.as_posix()}")
            if item.is_file():
                if item.stat().st_size > MAX_FILE_SIZE:
                    raise PackageError(f"File exceeds {MAX_FILE_SIZE} bytes: {relative.as_posix()}")
                files[relative.as_posix()] = item.read_bytes()
                _check_total(files)
        return files
    try:
        archive = zipfile.ZipFile(BytesIO(root.read_bytes()))
    except (zipfile.BadZipFile, OSError) as exc:
        raise PackageError(f"{path} is neither a directory nor a valid ZIP archive.") from exc
    with archive:
        for info in archive.infolist():
            raw = info.filename.replace("\\", "/")
            parts = PurePosixPath(raw).parts
            if PurePosixPath(raw).is_absolute() or ".." in parts or (parts and ":" in parts[0]):
                raise PackageError(f"Unsafe ZIP path: {raw}")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise PackageError(f"Symlink entries are not allowed: {raw}")
            if info.is_dir():
                continue
            if info.file_size > MAX_FILE_SIZE:
                raise PackageError(f"File exceeds {MAX_FILE_SIZE} bytes: {raw}")
            files[str(PurePosixPath(raw)).lstrip("./")] = archive.read(info)
            _check_total(files)
    return files


# --------------------------------------------------------------------------------------------- decoding

def _printable(text: str, min_length: int = 6) -> bool:
    if len(text) < min_length:
        return False
    good = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return good / len(text) > 0.95 and sum(ch.isalpha() for ch in text) >= min(3, min_length)


def _try_base64(run: str) -> str | None:
    if run.isdigit() or run.isalpha() and (run.islower() or run.isupper()):
        return None  # plain words and numbers are not encodings
    try:
        decoded = base64.b64decode(run + "=" * (-len(run) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if _printable(decoded) else None


def decode_text(text: str, location: str, trail: list[dict[str, str]], max_rounds: int = 5) -> str:
    """Return the text with hidden content revealed. Decoded payloads are appended, not substituted, so the original
    stays visible and line references for the original text stay valid."""
    revealed: list[str] = []

    def note(technique: str, before: str, after: str) -> None:
        trail.append({"location": location, "technique": technique, "before": before[:120], "after": after[:200]})

    if ZERO_WIDTH.search(text):
        stripped = ZERO_WIDTH.sub("", text)
        joined = [w for w in re.findall(r"\S*[​-‏⁠-⁤﻿­]\S*", text)][:3]
        note("zero-width characters", " ".join(joined), ZERO_WIDTH.sub("", " ".join(joined)))
        text = stripped

    def fold(match: re.Match[str]) -> str:
        word = match.group(0)
        # Only words that mix plain Latin letters with lookalike letters (e.g. a Cyrillic "і" in "gіthub.com").
        # Math and typographic symbols such as "²" or "ℝ" are ordinary text, not disguise.
        if re.search(r"[A-Za-z]", word) and any(ord(ch) > 127 and ch.isalpha() for ch in word):
            plain = unicodedata.normalize("NFKC", word).translate(CONFUSABLES)
            if plain != word and re.fullmatch(r"[\x00-\x7f]+", plain):
                note("lookalike characters", word, plain)
                return plain
        return word

    text = re.sub(r"[^\s`'\"<>()\[\]]+", fold, text)

    current = text
    for _ in range(max_rounds):
        found: list[str] = []
        for match in ESCAPES.finditer(current):
            try:
                after = match.group(0).encode("ascii").decode("unicode_escape")
            except UnicodeDecodeError:
                continue
            if _printable(after):
                note("string escapes", match.group(0), after)
                found.append(after)
        for match in CHR_CHAIN.finditer(current):
            after = "".join(chr(int(n)) for n in re.findall(r"\d+", match.group(0)) if 9 <= int(n) < 127)
            if _printable(after, min_length=3):  # short command names like "wget" are the point
                note("character codes", match.group(0), after)
                found.append(after)
        for match in FROM_CHAR_CODE.finditer(current):
            after = "".join(chr(int(n)) for n in re.findall(r"\d+", match.group(1)) if 9 <= int(n) < 127)
            if _printable(after, min_length=3):  # short command names like "wget" are the point
                note("character codes", match.group(0), after)
                found.append(after)
        for match in SPLIT_LITERALS.finditer(current):
            pieces = re.findall(QUOTED, match.group(0))
            after = "".join(piece[1:-1] for piece in pieces)
            if len(pieces) >= 2 and len(after) >= 4:
                note("split string literals", match.group(0), after)
                found.append(after)
        for match in BASE64_RUN.finditer(current):
            after = _try_base64(match.group(0))
            if after:
                note("base64", match.group(0), after)
                found.append(after)
        for match in HEX_RUN.finditer(current):
            try:
                after = bytes.fromhex(match.group(0)).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if _printable(after):
                note("hex", match.group(0), after)
                found.append(after)
        new = [piece for piece in found if piece not in revealed]
        if not new:
            break
        revealed.extend(new)
        current = "\n".join(new)  # the next round looks inside what was just revealed (stacked encodings)
    return text if not revealed else text + "\n" + "\n".join(revealed)


# --------------------------------------------------------------------------------------------- extraction

def _active_lines(path: str, text: str) -> list[tuple[int, str, bool]]:
    """(line number, line, is_code) for each line. In Markdown, only fenced code, inline code and lines with a
    command-like cue count as code: a documentation link is not a capability, an instruction to run curl is."""
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in SCRIPT_SUFFIXES or text.startswith("#!"):
        return [(n, line, True) for n, line in enumerate(text.splitlines(), 1)]
    # A ```markdown block is a document template (an ADR, a runbook); its links are prose, not commands.
    rows, fenced, prose_fence = [], False, False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            words = line.strip()[3:].split()
            prose_fence = fenced and bool(words) and words[0].lower() in PROSE_FENCES
            continue
        if fenced and not prose_fence:
            rows.append((n, line, True))
        elif "`" in line:
            # Outside a code block only the inline code counts: "use `curl`" is an instruction, while the prose
            # and link targets around it ("see [docs](https://...)") are not capabilities.
            # " ; " keeps separate code spans apart: `npm install` and `require('x')` must not read as one command.
            rows.append((n, " ; ".join(INLINE_CODE.findall(line)), True))
            rows.append((n, line, False))
        else:
            rows.append((n, line, False))
    return rows


def _add_delete_scope(manifest: Manifest, line: str) -> None:
    scope = delete_scope(line)
    if scope:
        for name in ("rm -rf", "Remove-Item -Recurse"):
            manifest.scope("destructive_operations", name, scope)


def _add_config_writes(manifest: Manifest, line: str, location: str, *, prose: bool, written=frozenset()) -> None:
    for name, pattern in AGENT_CONFIG:
        for match in re.finditer(pattern, line):
            reason = config_write(line, match.start(), match.end(), prose=prose, written=written)
            if reason:
                manifest.add("agent_config_writes", name, location)
                manifest.reasons.setdefault(f"agent_config_writes|{name}", reason)
                break
        else:
            if re.search(pattern, line):
                manifest.mention("agent_config_writes", name, location)


def _path_token(line: str, start: int, end: int) -> str:
    while start > 0 and line[start - 1] not in " \t\"'`(=,[{<":
        start -= 1
    while end < len(line) and line[end] not in " \t\"'`),;]}>|&":
        end += 1
    return line[start:end]


def own_env_files(lines: list[str], written: set[str] | frozenset[str] = frozenset()) -> set[str]:
    """The .env paths a file itself writes (a fixture, a template it creates): the skill's own file, not a secret."""
    env = dict(CREDENTIALS)[".env file"]
    own: set[str] = set()
    for line in lines:
        for match in re.finditer(env, line, re.I):
            if config_write(line, match.start(), match.end(), prose=False, written=written):
                own.add(_path_token(line, match.start(), match.end()))
    return own


def credential_reason(name: str, line: str, match: re.Match, own_env: set[str], fixture_file: bool) -> str:
    """Why a credential pattern match is an access, or "" when the secret is only named or is the skill's own file."""
    if name == ".env file" and own_env and (fixture_file or _path_token(line, match.start(), match.end()) in own_env):
        return ""  # a .env this file writes itself (in a test, any .env in it is the test's fixture)
    if SEARCH_TERM.search(re.split(r"\|", line[: match.start()])[-1]) and not CREDENTIAL_FILE.search(match.group(0)):
        return ""
    return "read or opened"


def _add_credentials(manifest: Manifest, line: str, location: str, own_env: set[str], fixture_file: bool) -> None:
    for name, pattern in CREDENTIALS:
        matches = list(re.finditer(pattern, line, re.I))
        if not matches:
            continue
        reasons = [credential_reason(name, line, m, own_env, fixture_file) for m in matches]
        reason = next((r for r in reasons if r), "")
        if reason:
            manifest.add("credential_access", name, location)
            manifest.reasons.setdefault(f"credential_access|{name}", reason)
        else:
            manifest.mention("credential_access", name, location)


def _scan_patterns(manifest: Manifest, category: str, patterns: list[tuple[str, str]], line: str, location: str) -> None:
    for name, pattern in patterns:
        if re.search(pattern, line, re.I if category != "agent_config_writes" else 0):
            manifest.add(category, name, location)


def _reveals_capability(text: str) -> bool:
    if URL.search(text) or INSTALL.search(text) or ENV_READ.search(text):
        return True
    groups = (NETWORK_CLIENTS, PROCESS_EXEC, PERSISTENCE, SHELL_RC, CREDENTIALS, DESTRUCTIVE, AGENT_CONFIG, AGENT_SPAWNING)
    return any(re.search(pattern, text, re.I) for group in groups for _, pattern in group)


MESSAGE_CALLS = {"print", "debug", "info", "warning", "warn", "error", "exception", "critical", "fail", "echo", "secho", "write", "log", "skip", "xfail"}
REGEX_CALLS = {"compile", "search", "match", "fullmatch", "sub", "subn", "findall", "finditer", "split"}
COMPARE_CALLS = {"startswith", "endswith", "removeprefix", "removesuffix"}
HELP_KEYWORDS = {"help", "description", "epilog", "usage", "metavar", "short_help"}


def _string_role(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    """Why a Python string literal is there: 'docstring', 'message', 'regex', 'compare' (mentions) or 'data'."""
    parent = parents.get(node)
    while isinstance(parent, (ast.JoinedStr, ast.FormattedValue, ast.BinOp)):  # f-string parts and "a" + "b"
        node, parent = parent, parents.get(parent)
    if isinstance(parent, ast.Expr):
        return "docstring"
    if isinstance(parent, ast.Compare):
        return "compare"
    if isinstance(parent, ast.keyword) and parent.arg in HELP_KEYWORDS:
        return "message"  # argparse/click help text describes an option; it does not run it
    if isinstance(parent, ast.Call) and node is not parent.func:
        func = parent.func
        name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
        if name in MESSAGE_CALLS or name.endswith(("Error", "Exception", "Warning")):
            return "message"
        if name in COMPARE_CALLS:
            return "compare"
        if name in REGEX_CALLS and isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in {"re", "regex"}:
            return "regex"
    return "data"


def _mask_python(text: str) -> str:
    """Blank (with spaces, keeping line breaks) Python string literals that only describe things: docstrings,
    log/error messages, comparison operands and regex patterns. "PowerShell redirection is UTF-16" in a message,
    a docstring about removed `npx` behaviour, or os\\.environ inside a regex is not the skill doing it. Strings
    handed to other calls (subprocess, os.system, requests, b64decode...) stay, so payloads are still scanned."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return text
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    lines = text.splitlines(keepends=True)
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))

    def char_offset(lineno: int, col_bytes: int) -> int:
        line = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
        return starts[lineno - 1] + len(line.encode("utf-8")[:col_bytes].decode("utf-8", "ignore"))
    chars = list(text)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)) or getattr(node, "end_lineno", None) is None:
            continue
        if _string_role(node, parents) == "data":
            continue
        start, end = char_offset(node.lineno, node.col_offset), char_offset(node.end_lineno, node.end_col_offset)
        for i in range(start, min(end, len(chars))):
            if chars[i] not in "\r\n":
                chars[i] = " "
    return "".join(chars)


def _not_a_target_ip(address: str, in_doc: bool) -> bool:
    """Addresses that are not a place a skill connects to: network ranges and masks (x.x.x.0, 255.x), documentation
    ranges (RFC 5737), multicast and reserved space, and private or link-local examples in documentation. Private
    addresses in shipped scripts are kept (a script that talks to 10.0.0.5 does reach the local network), and so is
    the cloud metadata address everywhere: an instruction to query it is a credential-theft shape."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if address in METADATA_ADDRESSES:
        return False
    if ip.version == 4 and (address.endswith(".0") or address.startswith("255.")):
        return True
    documentation = any(ip in net for net in DOC_NETS)
    return documentation or ip.is_multicast or ip.is_reserved or ip.is_unspecified or (in_doc and (ip.is_private or ip.is_link_local))


DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
METADATA_ADDRESSES = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}


# --------------------------------------------------------------------------------------------- hooks
#
# A hook is code the agent runs by itself on an event (session start, before every tool call, on every prompt),
# with no instruction and no approval step at the moment it runs. An update that registers a new hook gains
# something no skill text can: it acts on every session whether or not the skill is used. Hooks live in
# hooks.json files (Claude Code plugins nest handlers under matcher groups; GitHub Copilot puts handlers with
# `bash`/`powershell` keys directly under the event), in `.claude/settings.json`, in plugin.json, and in
# Markdown frontmatter. The parser goes by structure, not file name, so a renamed file (claude-hooks.json) is read.
# Mechanism from the NVIDIA SkillEvaluator study (2026-11-17); written here from the file formats, no code taken.

HOOK_COMMAND_KEYS = ("command", "bash", "powershell", "windows", "linux", "osx", "cmd")
SCRIPT_TOKEN = re.compile(r"([\w.-]+\.(?:sh|bash|ps1|psm1|cmd|bat|py|js|mjs|cjs|ts|rb|pl))\b", re.I)
INTERPRETERS = {"bash", "sh", "zsh", "node", "python", "python3", "pwsh", "powershell", "&", "uv", "run", "uvx", "exec", "cmd", "/c"}
HOOK_TEXT_GROUPS = (("network_clients", NETWORK_CLIENTS), ("process_execution", PROCESS_EXEC), ("persistence", PERSISTENCE + SHELL_RC),
                    ("credential_access", CREDENTIALS), ("destructive_operations", DESTRUCTIVE), ("agent_spawning", AGENT_SPAWNING))


SHELL_WORDS = {"if", "then", "else", "elif", "fi", "for", "do", "done", "while", "[", "[[", "test", "exit", "true", "false", "case", "esac", "{", "}", "!"}
RUNNERS = {"npx", "bunx", "uvx", "pipx", "dlx"}


def _hook_target(command: str) -> str:
    """What a command hook runs, stable across rewording: the script's file name, else the program (for a package
    runner, the package without its version), skipping inline shell guards such as `if [ -f x ]; then exit 0; fi`."""
    script = SCRIPT_TOKEN.search(command)
    if script:
        return script.group(1)
    for segment in re.split(r";|&&|\|\||\n", command):
        tokens = [t.strip("\"'`") for t in segment.split()]
        tokens = [t for t in tokens if t]
        if not tokens or tokens[0].lower() in SHELL_WORDS:
            continue
        for index, token in enumerate(tokens):
            if token.lower() in INTERPRETERS or token.startswith("-"):
                continue
            if token.lower() in RUNNERS or (token.lower() in {"pnpm", "yarn"} and index + 1 < len(tokens) and tokens[index + 1] == "dlx"):
                package = next((t for t in tokens[index + 1:] if not t.startswith("-") and t != "dlx"), "")
                return f"{token.lower()} {re.sub(r'(?<=.)@[^/@]*$', '', package)}".strip()
            return PurePosixPath(token.replace("\\", "/")).name or token
    return command.strip()[:40]


def _hook_handlers(events: Any) -> list[tuple[str, str, dict]]:
    """(event, matcher, handler) for each handler in a `hooks` object, in either nesting style."""
    found = []
    if not isinstance(events, dict):
        return found
    for event, groups in events.items():
        for group in groups if isinstance(groups, list) else [groups]:
            if not isinstance(group, dict):
                continue
            matcher = str(group.get("matcher") or "*")
            inner = group.get("hooks")
            for handler in inner if isinstance(inner, list) else [group]:
                if isinstance(handler, dict):
                    found.append((str(event), matcher, handler))
    return found


def _add_hooks(manifest: Manifest, path: str, suffix: str, text: str) -> None:
    events, base_line = None, 1
    if suffix == ".json" and '"hooks"' in text:
        try:
            data = json.loads(text)
        except ValueError:
            if "hook" in PurePosixPath(path).name.lower():
                manifest.add("hooks", f"unreadable hooks file: {path}", path)  # a hooks file nobody can read is a finding
            return
        events = data.get("hooks") if isinstance(data, dict) else None
    elif suffix == ".md":
        match = FRONTMATTER.match(text)
        if not match or "hooks" not in match.group(1):
            return
        try:
            data = yaml.safe_load(match.group(1))
        except yaml.YAMLError:
            return
        events = data.get("hooks") if isinstance(data, dict) else None
        base_line = text.count("\n", 0, text.find("hooks:")) + 1 if "hooks:" in text else 1
    for event, matcher, handler in _hook_handlers(events):
        kind = str(handler.get("type") or "command")
        command = next((str(handler[k]) for k in HOOK_COMMAND_KEYS if handler.get(k)), "")
        if command and isinstance(handler.get("args"), list):
            command = " ".join([command, *map(str, handler["args"])])  # {"command": "node", "args": ["hook.mjs"]}
        if kind == "http" or handler.get("url"):
            host = URL.search(str(handler.get("url", "")))
            target = host.group(1).lower() if host else "url"
        elif kind == "mcp_tool":
            target = str(handler.get("tool") or handler.get("server") or "tool")
        elif command:
            target = _hook_target(command)
        else:
            target = kind
        offset = text.find(command.replace('"', '\\"')[:60]) if command else -1
        line = text.count("\n", 0, offset) + 1 if offset >= 0 else base_line
        location = f"{path}:{line}"
        # The matcher is left out of the identity: widening "startup|resume" to "startup|resume|clear" is the same
        # hook, not a new one (seen in obra/superpowers history). Known limit: a narrow-to-wide matcher change
        # ("Bash" -> ".*") is therefore not reported either; that belongs to the scope work in P5.
        manifest.add("hooks", f"{event} {kind}: {target}", location)
        manifest.scope("hooks", f"{event} {kind}: {target}", matcher_scope(matcher))
        for value in [command, str(handler.get("url", ""))]:
            if not value:
                continue
            # The hook's own command line runs unattended, so it is read as code.
            for category, patterns in HOOK_TEXT_GROUPS:
                _scan_patterns(manifest, category, patterns, value, location)
            _add_delete_scope(manifest, value)
            for host in URL.finditer(value):
                name = host.group(1).lower()
                if not NOT_EXTERNAL.match(name) and not PLACEHOLDER_HOST.search(name):
                    manifest.add("network_hosts", name, location)
            for install in INSTALL.finditer(value):
                groups = [g for g in install.groups() if g]
                manifest.add("package_installs", f"{re.sub(chr(92) + 's+', ' ', groups[0]).lower()}:{groups[-1]}", location)


def build_manifest(files: dict[str, bytes]) -> dict[str, Any]:
    manifest = Manifest(files=len(files))
    for path in sorted(files):
        raw = files[path]
        suffix = PurePosixPath(path).suffix.lower()
        is_binary = suffix in BINARY_SUFFIXES or raw[:4] in {b"\x7fELF", b"MZ\x90\x00"} or raw[:2] == b"MZ" or b"\x00" in raw[:4096]
        if is_binary and suffix not in TEXT_SUFFIXES:
            manifest.add("bundled_binaries", path, path)
            continue
        vendored = VENDORED.match(path)
        if vendored:
            manifest.add("package_installs", "vendored:" + vendored.group(1), vendored.group(1))
            continue
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            manifest.add("bundled_binaries", path, path)
            continue
        if path == "SKILL.md":  # only the skill's own manifest declares its tools
            tools, key_line = _declared_tools(text)
            for tool in tools:
                manifest.add("declared_tools", tool, f"SKILL.md:{key_line}")
        if not TEST_PATH.search(path):
            _add_hooks(manifest, path, suffix, text)
        trail_start = len(manifest.decode_trail)
        if suffix == ".py":
            text = _mask_python(text)
        is_test = bool(TEST_PATH.search(path) or TEST_NAME.match(PurePosixPath(path).name))
        decoded = decode_text(text, path, manifest.decode_trail)
        for step in manifest.decode_trail[trail_start:]:
            # Hiding matters when it hides something: count a technique only if what it revealed is itself a
            # capability (a host, a command, a config path...). Ordinary "a" + "b" joins are not disguise.
            if _reveals_capability(step["after"]):
                step["revealed_capability"] = "yes"
                manifest.add("hiding_techniques", step["technique"], path)
        original_lines = len(text.splitlines())
        if suffix in SCRIPT_SUFFIXES and not is_test:
            for name, pattern in ARGV_AGENT:
                for match in pattern.finditer(text):
                    manifest.add("agent_spawning", name, f"{path}:{text.count(chr(10), 0, match.start()) + 1}")
        lines = _active_lines(path, decoded)
        called = called_names([text for _, text, code in lines if code]) if suffix in SCRIPT_SUFFIXES else frozenset()
        written = written_names([text for _, text, code in lines if code]) if suffix in SCRIPT_SUFFIXES else frozenset()
        run_names = exec_names([text for _, text, code in lines if code]) if suffix in SCRIPT_SUFFIXES else frozenset()
        string_quotes = ('"', "'", "`") if suffix in {".js", ".mjs", ".cjs", ".ts"} else ('"', "'")
        anti_example, last_number = False, 0
        own_env = own_env_files([text for _, text, code in lines if code], written)
        source_lines = decoded.splitlines()

        def original_line(number: int, fallback: str) -> str:
            return source_lines[number - 1] if 0 < number <= len(source_lines) else fallback
        for index, (number, line, is_code) in enumerate(lines):
            location = f"{path}:{number}" if number <= original_lines else f"{path}:decoded"
            if number > original_lines:
                is_code = True  # revealed payloads are always treated as code
            in_comment = is_code and number <= original_lines and bool(COMMENT_LINE.match(line)) and suffix in SCRIPT_SUFFIXES
            if in_comment:
                continue  # a comment describes code; it does not run (license headers, notes about attacks)
            full_line = original_line(number, line)
            inline_row = suffix in DOC_SUFFIXES and is_code and line != full_line
            fenced_row = suffix in DOC_SUFFIXES and is_code and not inline_row and number <= original_lines
            if not fenced_row or number != last_number + 1 or not line.strip():
                anti_example = False  # an example's marker covers its own lines, up to a blank line or the fence end
            last_number = number
            if fenced_row and DOC_COMMENT.match(line):
                anti_example = bool(ANTI_EXAMPLE.match(line))
                continue  # a comment inside a fenced example ("# Available at: https://...")
            if fenced_row and anti_example:
                continue  # under "// VULNERABLE" or "# BAD": what not to write, shown to be avoided
            cue = is_code or bool(FETCH_CUE.search(line))
            previous = lines[index - 1][1] if index > 0 else ""
            neighbours = [n for n in (previous, lines[index + 1][1] if index + 1 < len(lines) else "") if n]
            hosts_apply = not is_test and not ECHO_LINE.match(line) and not (suffix in DOC_SUFFIXES and TABLE_ROW.match(full_line))
            if cue and hosts_apply and PurePosixPath(path).name.lower() not in LOCKFILES:
                for match in URL.finditer(line):
                    host = match.group(1).lower().strip("[]")
                    if NAMESPACE_CONTEXT.search(line[: match.start()]) or NOT_EXTERNAL.match(host) or host in IDENTIFIER_HOSTS:
                        continue
                    if NOT_CONTACTED_CONTEXT.search(line[: match.start()]):
                        continue
                    if inline_row and PROVENANCE.search(full_line):
                        # "Adapted from `x.md` in the `https://github.com/x/y` repo" credits a source. Only provenance
                        # lines: a bare URL span is otherwise often a real API base ("Base: `https://api.x/v1`"),
                        # and a broader rule lost 9 true hosts on held-out 2.
                        continue
                    if PLACEHOLDER_HOST.search(host) or _not_a_target_ip(host, suffix in DOC_SUFFIXES) or CSP_LINE.search(line):
                        continue
                    if not is_code and not _prose_cue(line, match.start()):
                        continue
                    if "<!DOCTYPE" in line[: match.start()].upper():
                        continue  # a DTD reference names a document type; nothing is fetched
                    if host.endswith("."):
                        continue  # a templated host such as https://aws-external-anthropic.{region}.api.aws
                    rest = line[match.end():]
                    if BRACKET_SEGMENT.match(rest):
                        continue
                    if PLACEHOLDER_PATH.match(rest) and not (suffix in SCRIPT_SUFFIXES and re.match(r"^/(?:\{|\$\{)", rest)):
                        continue  # a template link such as https://github.com/owner/repo/pull/123; in code, {x} is interpolation
                    if number > original_lines:
                        reason = "revealed by decoding hidden text"
                    elif is_code:
                        if inline_row:
                            # An inline span from a prose line: judge it in its sentence ("Use URL `https://...`").
                            at = full_line.find(match.group(0))
                            prose_before = original_line(number - 1, "") if number > 1 else ""
                            reason = contact_reason(full_line, at, path, (), prose_before) if at >= 0 else ""
                        else:
                            reason = contact_reason(line, match.start(), path, neighbours, previous, called)
                    else:
                        reason = "an instruction to fetch or send"
                    if not reason:
                        manifest.mention("network_hosts", host, location)
                        continue
                    manifest.add("network_hosts", host, location)
                    manifest.reasons.setdefault(f"network_hosts|{host}", reason)
                if is_code:
                    for ip_match in IPV4.finditer(line):
                        ip = ip_match.group(0)
                        if re.match(r"/\d{1,2}\b", line[ip_match.end():]):
                            continue  # "3.40.9.80/28" is an address range (an allowlist entry), not a target
                        if IP_DATA_KEY.search(line[: ip_match.start()]) or CSP_LINE.search(line):
                            continue  # a field of a sample log record, or a browser allowlist
                        if all(0 <= int(octet) <= 255 for octet in ip.split(".")) and not ip.startswith(("0.", "127.")) and not _not_a_target_ip(ip, suffix in DOC_SUFFIXES):
                            reason = ("revealed by decoding hidden text" if number > original_lines
                                      else contact_reason(line, ip_match.start(), path, neighbours, previous, called))
                            if not reason:
                                manifest.mention("network_hosts", ip, location)
                                continue
                            manifest.add("network_hosts", ip, location)
                            manifest.reasons.setdefault(f"network_hosts|{ip}", reason)
            if not is_code:
                # Prose still matters for the two most specific attacks: an instruction to write to agent
                # configuration ("append this to ~/.claude/CLAUDE.md") or to a startup file. Both need a write
                # verb on the same line; network and execution patterns stay code-only because prose mentions
                # of tools are common and harmless.
                if not TABLE_ROW.match(original_line(number, line)):
                    _add_config_writes(manifest, line, location, prose=True)
                if WRITE_CUE.search(line) and not TABLE_ROW.match(original_line(number, line)):
                    _scan_patterns(manifest, "persistence", PERSISTENCE + SHELL_RC, line, location)
                continue
            command_line = all_spans = line
            if inline_row:
                # An inline-code row from Markdown prose. Drop spans the sentence negates ("Never run its setup
                # scripts or `curl | sh`"), and treat a single bare word (`curl`, `os.environ`, `httpx.Client`,
                # `~/Library/LaunchAgents` listed as an indicator) as a mention: a command has arguments.
                spans = [m.group(1) for m in INLINE_CODE.finditer(full_line) if not NEGATED.search(full_line[: m.start()][-60:])]
                all_spans = " ; ".join(spans)
                command_line = " ; ".join(s for s in spans if len(s.split()) > 1)
            alternation_free = ALTERNATION.sub(" ", command_line)  # "curl|wget|nc", "{zsh|bash|powershell}" are lists
            _scan_patterns(manifest, "network_clients", NETWORK_CLIENTS, alternation_free, location)
            for name, pattern in PROCESS_EXEC:
                found = re.search(pattern, command_line if name == "pipe-to-shell" else alternation_free, re.I)
                if not found:
                    continue
                at = line.find(found.group(0)) if found.group(0) in line else -1
                if name == "powershell" and SETTING_SHELL.search(alternation_free[: found.start()]):
                    continue  # `shell: pwsh` in a workflow names the shell of a CI step
                if not inline_row and in_message_string(line, max(at, 0), suffix not in DOC_SUFFIXES):
                    continue  # inside a message or fixture sentence: "...unavailable in this PowerShell script"
                reason = "called in code"
                if number > original_lines:
                    reason = "revealed by decoding hidden text"
                elif not inline_row and at >= 0 and suffix not in SHELL_SCRIPT_SUFFIXES:
                    reason = exec_reason(line, at, previous=previous, names=run_names, quotes=string_quotes)
                    if not reason:
                        manifest.mention("process_execution", name, location)
                        continue  # a sample or fixture string holding code as text, never run
                manifest.add("process_execution", name, location)
                manifest.reasons.setdefault(f"process_execution|{name}", reason)
            _scan_patterns(manifest, "persistence", PERSISTENCE, command_line, location)
            if WRITE_CUE.search(command_line):
                _scan_patterns(manifest, "persistence", SHELL_RC, command_line, location)
            _add_credentials(manifest, command_line, location, own_env, is_test)
            _scan_patterns(manifest, "destructive_operations", DESTRUCTIVE, command_line, location)
            _add_delete_scope(manifest, command_line)
            _scan_patterns(manifest, "agent_spawning", AGENT_SPAWNING, command_line, location)
            if not TABLE_ROW.match(full_line):
                if inline_row:
                    # A span in a prose line: an instruction in its sentence ("Add this to `~/.claude/settings.json`"),
                    # or a write inside the span itself (`echo x >> CLAUDE.md`).
                    _add_config_writes(manifest, full_line, location, prose=True)
                    _add_config_writes(manifest, all_spans, location, prose=False)
                else:
                    _add_config_writes(manifest, line, location, prose=False, written=written)
                    if suffix in DOC_SUFFIXES and YAML_TEXT_VALUE.match(line):
                        # A text value in front matter or YAML in docs ("short-description: Update AGENTS.md with
                        # design system rules") is a sentence: read it as prose.
                        _add_config_writes(manifest, line, location, prose=True)
            for match in ENV_READ.finditer(all_spans):
                name = next(g for g in match.groups() if g).upper()
                if not is_secret_env(name):
                    continue  # $env:APPDATA is a folder, AGENT_ID an identifier, PORT configuration: not secrets
                manifest.add("credential_access", "env:" + name, location)
            if ENV_ALL.search(command_line):
                manifest.add("credential_access", "env:<all>", location)
            if is_test:
                continue  # an install command inside a test's string data is test input, not something run
            for match in INSTALL.finditer(line):
                full = original_line(number, line)
                command = " ".join(match.group(0).split()[:2])  # e.g. "npm install", findable in the original line
                if NEGATED.search(full[: max(0, full.find(command))][-40:]):
                    continue  # "do not run `npm install` first" is the opposite of an install
                groups = [g for g in match.groups() if g]
                tool = "uv" if match.group(3) else re.sub(r"\s+", " ", groups[0]).lower()
                tool = TOOL_ALIASES.get(tool, tool)
                package = groups[-1].strip(".,;:)\"'`").rstrip("@")  # "@ag-ui/client@<pinned version>" -> the name
                if package and not package.startswith("-") and package.lower() not in STOP_PACKAGES and not PLACEHOLDER_TOKEN.search(package):
                    manifest.add("package_installs", f"{tool}:{package}", location)
                    if tool in MULTI_INSTALL_TOOLS and "://" not in package:
                        for extra in _more_packages(line[match.end():]):
                            manifest.add("package_installs", f"{tool}:{extra}", location)
    return manifest.to_dict()


TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|spec)/", re.I)
TEST_NAME = re.compile(r"^(?:test_.*|.*_test\.\w+|.*\.(?:test|spec)\.\w+|conftest\.py|self_?test\.\w+)$", re.I)
DOC_SUFFIXES = {".md", ".txt", ".rst"}


def source_kind(location: str) -> str:
    """Where a capability lives: 'instructions' (Markdown the agent reads and follows), 'shipped' (scripts and
    files that ship and can run), or 'test' (test files only). Instructions are not lower risk than code: for a
    skill they are what the agent is told to do."""
    path = location.rsplit(":", 1)[0] if re.search(r":(?:\d+|decoded)$", location) else location
    name = PurePosixPath(path).name
    if TEST_PATH.search(path) or TEST_NAME.match(name):
        return "test"
    if PurePosixPath(name).suffix.lower() in DOC_SUFFIXES:
        return "instructions"
    return "shipped"


def _hook_additions(before: dict[str, list[str]], after: dict[str, list[str]], gained: dict[str, list[str]]) -> tuple[dict[str, list[str]], list[str]]:
    """Split new hook values into real additions and re-pointings. A hook is added when an event gains a handler
    (a new event, a new client's event name, or one more handler on an event); a handler that only switches to
    another script on an event that already had as many handlers is a change, not a new capability (real plugin
    histories: 42 of 65 new hook values were .sh <-> .js ports or wrapper swaps). What the new script does is still
    read, because the script itself is scanned like any other file."""
    def count(values) -> dict[str, int]:
        counts: dict[str, int] = {}
        for value in values:
            key = value.split(":", 1)[0]  # "SessionStart command"
            counts[key] = counts.get(key, 0) + 1
        return counts
    old_counts = count(before)
    new_counts = count(after)
    kept, repointed = {}, []
    for value, locations in gained.items():
        key = value.split(":", 1)[0]
        if value.startswith("unreadable hooks file") or new_counts[key] > old_counts.get(key, 0):
            kept[value] = locations
        else:
            repointed.append(value)
    return kept, sorted(repointed)


def _widest(scopes: list[str]) -> str:
    return max(scopes, key=lambda scope: SCOPE_RANK.get(scope, 0))


def _widenings(old: dict[str, Any], new: dict[str, Any], added: dict[str, dict[str, list[str]]]) -> list[dict[str, Any]]:
    """Facts both versions have whose reach grew: rm -rf from a temp folder to the home folder, a hook from named
    tools to every tool, an allowed tool from `Bash(git:*)` to `Bash`. A manifest written before scopes were
    recorded has no "scopes" key; then reach is unknown, not narrow, and nothing is reported."""
    found = []
    old_scopes, new_scopes = old.get("scopes"), new.get("scopes") or {}
    if old_scopes is not None:
        for key, scopes in sorted(new_scopes.items()):
            before = old_scopes.get(key)
            category, value = key.split("|", 1)
            if not before or value in added.get(category, {}):
                continue
            wide, was = _widest(scopes), _widest(before)
            if SCOPE_RANK.get(wide, 0) > SCOPE_RANK.get(was, 0):
                found.append({"category": category, "value": value, "before": was, "after": wide,
                              "locations": new["capabilities"].get(category, {}).get(value, [])[:5]})
    before_tools = old["capabilities"].get("declared_tools", {})
    after_tools = new["capabilities"].get("declared_tools", {})
    for tool, locations in sorted(added.get("declared_tools", {}).items()):
        narrower = sorted(t for t in before_tools if t.startswith(tool + "(") and t not in after_tools)
        if "(" not in tool and narrower:
            found.append({"category": "declared_tools", "value": tool, "before": ", ".join(narrower), "after": "all uses",
                          "locations": locations[:5]})
    return found


def diff_manifests(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Capabilities the new version has that the old one did not (and the reverse)."""
    added: dict[str, dict[str, list[str]]] = {}
    removed: dict[str, list[str]] = {}
    repointed: list[str] = []
    for category in CATEGORIES:
        before, after = old["capabilities"].get(category, {}), new["capabilities"].get(category, {})
        gained = {value: locations for value, locations in after.items() if value not in before}
        lost = sorted(value for value in before if value not in after)
        if category == "hooks":
            gained, repointed[:] = _hook_additions(before, after, gained)
        if gained:
            added[category] = gained
        if lost:
            removed[category] = lost
    widened = _widenings(old, new, added)
    sources: dict[str, dict[str, list[str]]] = {}
    by_source = {"instructions": 0, "shipped": 0, "test": 0}
    for category, values in added.items():
        for value, locations in values.items():
            kinds = sorted({source_kind(location) for location in locations})
            sources.setdefault(category, {})[value] = kinds
            # An item counts once, under the riskiest place it appears: shipped code, then instructions, then tests.
            by_source[next(k for k in ("shipped", "instructions", "test") if k in kinds)] += 1
    return {
        "method": "capability_manifest_diff",
        "status": "new_capabilities" if added or widened else "no_new_capabilities",
        "added": added,
        "added_sources": sources,
        "added_by_source": by_source,
        "removed": removed,
        "hooks_repointed": repointed,
        "widened": widened,
        "added_scopes": {key: _widest(values) for key, values in (new.get("scopes") or {}).items()
                         if key.split("|", 1)[1] in added.get(key.split("|", 1)[0], {})},
        "new_categories": sorted(c for c in added if not old["capabilities"].get(c)),
        "limitations": "Compares extracted facts, not code. A capability that both versions mention is not reported even if how it is used changed.",
    }
