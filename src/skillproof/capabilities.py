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

MANIFEST_VERSION = "0.2.0"  # 0.2.0: agent_spawning category; secret-only env reads; vendored folders as one item

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
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
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
                      r"(?!\s+(?:-\S+\s+)*[\w./-]+\.(?:py|js|mjs|cjs|ts|sh)\b)"),  # data piped into a local script is not code
    ("powershell", r"\bpowershell(?:\.exe)?\b|\bpwsh\b"), ("cmd /c", r"\bcmd(?:\.exe)?\s+/c\b"),
]
AGENT_CONFIG = [
    ("CLAUDE.md", r"CLAUDE\.md"), ("AGENTS.md", r"AGENTS\.md"), (".claude/settings", r"\.claude[/\\]settings(?:\.local)?\.json"),
    (".claude/hooks", r"\.claude[/\\]hooks"), (".claude/commands", r"\.claude[/\\](?:commands|agents|skills)"),
    (".mcp.json", r"(?<![\w-])\.?mcp\.json"), (".cursorrules", r"\.cursorrules|\.cursor[/\\]rules"),
    ("copilot-instructions", r"copilot-instructions\.md"), (".codex", r"\.codex[/\\]"), ("GEMINI.md", r"GEMINI\.md"),
]
PERSISTENCE = [
    ("shell rc", r"\.(?:bashrc|zshrc|bash_profile|profile|zprofile)\b"), ("cron", r"\bcrontab\b|/etc/cron"),
    ("systemd", r"\bsystemctl\s+(?:--user\s+)?(?:enable|start)\b|/etc/systemd|\.config/systemd"), ("launchd", r"\blaunchctl\b|LaunchAgents|LaunchDaemons"),
    # A schedule handed to an API ("expression": "0 20 * * 5") runs an agent on a timer just like crontab does.
    ("cron schedule", r"[\"']?(?:expression|cron|schedule)[\"']?\s*[:=]\s*[\"'][0-9*/,\- ]{9,}[\"']"),
    ("windows run key", r"CurrentVersion\\+Run\b"), ("scheduled task", r"\bschtasks\b|Register-ScheduledTask"),
    ("startup folder", r"Start Menu\\+Programs\\+Startup"),
]
CREDENTIALS = [
    ("ssh keys", r"~?/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b"), ("aws credentials", r"\.aws[/\\]credentials|\bAWS_SECRET_ACCESS_KEY\b"),
    ("netrc", r"\.netrc\b"), ("npmrc/pypirc", r"\.npmrc\b|\.pypirc\b"), ("keychain", r"\bsecurity\s+find-(?:generic|internet)-password\b|\bkeyring\.get_password\b"),
    ("gh token", r"\bgh\s+auth\s+token\b"), ("browser data", r"Login Data|cookies\.sqlite|Local State"),
    (".env file", r"(?<![\w.}\])])\.env\b(?!\.example)"),  # "{path}.env" is attribute access, not a .env file
]
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
    parts = name.split("_")
    if "KEY" in parts and parts.index("KEY") + 1 < len(parts) and parts[parts.index("KEY") + 1] in {"VAULT", "VAULTS"}:
        parts = [p for i, p in enumerate(parts) if not (p == "KEY" and i + 1 < len(parts) and parts[i + 1] in {"VAULT", "VAULTS"})]
    if SECRET_ENV_SUBSTR.search(name):
        return True
    if LOCATOR_ENV.search(name):
        return False  # NEON_AUTH_JWKS_URL, AUTH_ISSUER: where to find something, not a secret
    return any(p in SECRET_ENV_PARTS for p in parts)
ECHO_LINE = re.compile(r"^\s*(?:echo|printf|Write-Host|Write-Output|log_\w+)\b[^|]*$")  # a URL that is only printed
DOC_COMMENT = re.compile(r"^\s*(?:#\s|//\s)")
STOP_PACKAGES = {"did", "not", "the", "a", "an", "it", "this", "that", "to", "and", "or", "will", "first", "then", "with", "from", "is", "was", "cache"}
ENV_ALL = re.compile(r"(?<!in )\bos\.environ\b(?![\[.(])|\bprocess\.env\b(?![.\[])|\bprintenv\b|\benv\s*\|")
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
PLACEHOLDER_TOKEN = re.compile(r"^<|<[A-Za-z]|^[A-Za-z_-]+>$")
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
    ("agent sdk", r"\bclaude_agent_sdk\b|@anthropic-ai/claude-agent-sdk|\bclaude_code_sdk\b|@anthropic-ai/claude-code\b"),
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
# Real local skill files showed four more harmless groups (VS Code / Copilot, Codex, Kimi and Claude skill copies):
# placeholder links ("github.com/owner/repo"), tool names inside a match pattern ("curl|wget|nc" in a hook that
# blocks them), location variables read as "credentials" ($env:APPDATA), and Markdown tables describing rules.
PLACEHOLDER_PATH = re.compile(r"^/(?:owner|org|user|username|your[\w-]*|my-?org|<[^>]+>|\{[^}]+\}|:\w+|\$\{?\w+\}?)(?:/|$)", re.I)
ALTERNATION = re.compile(r"(?<![\w|])[\w.-]+(?:\|[\w.-]+)+(?![\w|])")
LOCATION_ENV = re.compile(r"^(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA|PROGRAMDATA|PROGRAMFILES(?:\(X86\))?|TEMP|TMP|TMPDIR|PATH|PWD|OLDPWD|SHELL|USER|USERNAME|LOGNAME|LANG|LC_\w+|TERM|EDITOR|VISUAL|HOSTNAME|COMPUTERNAME|OS|XDG_\w+|CODEX_HOME|CLAUDE_CONFIG_DIR|CLAUDE_PROJECT_DIR|VSCODE_\w+|CI|GITHUB_WORKSPACE|RUNNER_TEMP|\w*_BASE_URL)$", re.I)
# Third-party code copied into the skill. Its own READMEs and changelogs are full of install lines, example hosts and
# addresses that describe that library, not the skill (held-out test: 20 of 93 false items came from one
# node_modules folder). The folder itself is reported once, as shipped third-party code; its contents are not listed.
VENDORED = re.compile(r"^(.*?(?:^|/)(?:node_modules|bower_components|site-packages|vendor|third_party|\.venv|venv))/")
# Placeholder hosts in examples: "my-vault.vault.azure.net", "your-resource.openai.azure.com", "x.example.workers.dev".
PLACEHOLDER_HOST = re.compile(r"^(?:my|your)[-_]|(?:^|\.)example(?:\.|$)|\.(?:internal|lan|home\.arpa)$", re.I)
TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")  # a Markdown table row starts and ends with |; a pipe continuation does not
WRITE_CUE = re.compile(r"(?:>>?|\btee\b|\bwrite|\bappend|\bopen\([^)]*['\"][wa]|\bcp\b|\bmv\b|\bcopy|\bmodify|\bedit|\badd\b[^.\n]{0,40}\bto\b|\binsert|\bupdate|\bWriteAllText|\bSet-Content|\bAdd-Content|\bOut-File|\bwriteFile|\bappendFile|\becho\b)", re.I)

CATEGORIES = (
    "network_hosts", "network_clients", "process_execution", "agent_config_writes", "persistence",
    "credential_access", "package_installs", "destructive_operations", "bundled_binaries", "hiding_techniques",
    "declared_tools", "agent_spawning",
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

    def add(self, category: str, value: str, location: str) -> None:
        locations = self.capabilities[category].setdefault(value, [])
        if location not in locations and len(locations) < 20:
            locations.append(location)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": MANIFEST_VERSION,
            "method": "decode_then_extract_facts",
            "files": self.files,
            "capabilities": {c: {v: sorted(locs) for v, locs in sorted(values.items())} for c, values in self.capabilities.items()},
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


def _scan_patterns(manifest: Manifest, category: str, patterns: list[tuple[str, str]], line: str, location: str) -> None:
    for name, pattern in patterns:
        if re.search(pattern, line, re.I if category != "agent_config_writes" else 0):
            manifest.add(category, name, location)


def _reveals_capability(text: str) -> bool:
    if URL.search(text) or INSTALL.search(text) or ENV_READ.search(text):
        return True
    groups = (NETWORK_CLIENTS, PROCESS_EXEC, PERSISTENCE, CREDENTIALS, DESTRUCTIVE, AGENT_CONFIG, AGENT_SPAWNING)
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
            if suffix in DOC_SUFFIXES and is_code and not inline_row and number <= original_lines and DOC_COMMENT.match(line):
                continue  # a comment inside a fenced example ("# Available at: https://...")
            cue = is_code or bool(FETCH_CUE.search(line))
            hosts_apply = not is_test and not ECHO_LINE.match(line) and not (suffix in DOC_SUFFIXES and TABLE_ROW.match(full_line))
            if cue and hosts_apply and PurePosixPath(path).name.lower() not in LOCKFILES:
                for match in URL.finditer(line):
                    host = match.group(1).lower().strip("[]")
                    if NAMESPACE_CONTEXT.search(line[: match.start()]) or NOT_EXTERNAL.match(host) or host in IDENTIFIER_HOSTS:
                        continue
                    if PLACEHOLDER_HOST.search(host) or _not_a_target_ip(host, suffix in DOC_SUFFIXES):
                        continue
                    if not is_code and not _prose_cue(line, match.start()):
                        continue
                    if "<!DOCTYPE" in line[: match.start()].upper():
                        continue  # a DTD reference names a document type; nothing is fetched
                    if host.endswith("."):
                        continue  # a templated host such as https://aws-external-anthropic.{region}.api.aws
                    rest = line[match.end():]
                    if PLACEHOLDER_PATH.match(rest) and not (suffix in SCRIPT_SUFFIXES and re.match(r"^/(?:\{|\$\{)", rest)):
                        continue  # a template link such as https://github.com/owner/repo/pull/123; in code, {x} is interpolation
                    manifest.add("network_hosts", host, location)
                if is_code:
                    for ip_match in IPV4.finditer(line):
                        ip = ip_match.group(0)
                        if re.match(r"/\d{1,2}\b", line[ip_match.end():]):
                            continue  # "3.40.9.80/28" is an address range (an allowlist entry), not a target
                        if all(0 <= int(octet) <= 255 for octet in ip.split(".")) and not ip.startswith(("0.", "127.")) and not _not_a_target_ip(ip, suffix in DOC_SUFFIXES):
                            manifest.add("network_hosts", ip, location)
            if not is_code:
                # Prose still matters for the two most specific attacks: an instruction to write to agent
                # configuration ("append this to ~/.claude/CLAUDE.md") or to a startup file. Both need a write
                # verb on the same line; network and execution patterns stay code-only because prose mentions
                # of tools are common and harmless.
                if WRITE_CUE.search(line) and not TABLE_ROW.match(original_line(number, line)):
                    _scan_patterns(manifest, "agent_config_writes", AGENT_CONFIG, line, location)
                    _scan_patterns(manifest, "persistence", PERSISTENCE, line, location)
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
                if re.search(pattern, command_line if name == "pipe-to-shell" else alternation_free, re.I):
                    manifest.add("process_execution", name, location)
            _scan_patterns(manifest, "persistence", PERSISTENCE, command_line, location)
            _scan_patterns(manifest, "credential_access", CREDENTIALS, command_line, location)
            _scan_patterns(manifest, "destructive_operations", DESTRUCTIVE, command_line, location)
            _scan_patterns(manifest, "agent_spawning", AGENT_SPAWNING, command_line, location)
            window = " ".join(row[1] for row in lines[max(0, index - 2): index + 3])
            if WRITE_CUE.search(window) and not TABLE_ROW.match(full_line):
                _scan_patterns(manifest, "agent_config_writes", AGENT_CONFIG, command_line, location)
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
TEST_NAME = re.compile(r"^(?:test_.*|.*_test\.\w+|.*\.(?:test|spec)\.\w+|conftest\.py)$", re.I)
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


def diff_manifests(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Capabilities the new version has that the old one did not (and the reverse)."""
    added: dict[str, dict[str, list[str]]] = {}
    removed: dict[str, list[str]] = {}
    for category in CATEGORIES:
        before, after = old["capabilities"].get(category, {}), new["capabilities"].get(category, {})
        gained = {value: locations for value, locations in after.items() if value not in before}
        lost = sorted(value for value in before if value not in after)
        if gained:
            added[category] = gained
        if lost:
            removed[category] = lost
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
        "status": "new_capabilities" if added else "no_new_capabilities",
        "added": added,
        "added_sources": sources,
        "added_by_source": by_source,
        "removed": removed,
        "new_categories": sorted(c for c in added if not old["capabilities"].get(c)),
        "limitations": "Compares extracted facts, not code. A capability that both versions mention is not reported even if how it is used changed.",
    }
