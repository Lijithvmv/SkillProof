"""Building the manifest: every file's active lines scanned for facts in their positions, hooks read from hook
definitions, per-file results cached and replayed."""
from __future__ import annotations

import ast
import ipaddress
import json
import hashlib
import re
import warnings

import yaml
from pathlib import PurePosixPath
from typing import Any

from skillproof.engines.capabilities.decoding import decode_text
from skillproof.engines.capabilities.model import Manifest
from skillproof.engines.capabilities.positions import AGENT_CONFIG, AGENT_INSTALL_DIR, AGENT_SPAWNING, ALTERNATION, ANTI_EXAMPLE, ARGV_AGENT, BINARY_SUFFIXES, BRACKET_SEGMENT, CHANGELOG_FILE, COMMENT_LINE, CREDENTIALS, CSP_LINE, DESTRUCTIVE, DOC_COMMENT, DOC_SUFFIXES, ECHO_LINE, ENV_ALL, ENV_INHERIT, ENV_OUT, ENV_READ, FETCH_CUE, FILE_COPY, FRONTMATTER, IDENTIFIER_HOSTS, INLINE_CODE, INSTALL, IPV4, IP_DATA_KEY, LIST_ITEM, LOCAL_BIN, LOCATE_BEFORE, LOCKFILES, MULTI_INSTALL_TOOLS, NAMESPACE_CONTEXT, NEGATED, NEGATED_LABEL, NETWORK_CLIENTS, NOT_CONTACTED_CONTEXT, NOT_EXTERNAL, PERSISTENCE, PLACEHOLDER_ARG, PLACEHOLDER_HOST, PLACEHOLDER_PATH, PLACEHOLDER_TOKEN, PROCESS_EXEC, PROSE_FENCES, PROVENANCE, SCRIPT_SUFFIXES, SETTING_SHELL, SHELL_RC, SHELL_SCRIPT_SUFFIXES, STOP_PACKAGES, TABLE_ROW, TEST_NAME, TEST_PATH, TEXT_SUFFIXES, TOOL_ALIASES, URL, VENDORED, WRITE_CUE, YAML_TEXT_VALUE, _declared_tools, _more_packages, _prose_cue, called_names, config_write, contact_reason, delete_scope, describes_span, exec_names, exec_reason, in_message_string, is_secret_env, joined_path_line, mask_search_patterns, matcher_scope, written_names


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
    if line[: match.start()].endswith("\\"):
        return ""  # "^(?:\\.netrc|\\.npmrc)$": a pattern in a deny-list of sensitive names, not a file opened
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


# A client named but not used: arguments that are only an ellipsis (`httpx.Client(...)`, `curl … | bash` describe a
# call's shape), a regex escape after the name (`axios\.` in a search pattern), or the bare name as a whole string
# ("curl",  # in a blocked-commands list).
# `httpx.Client(...)` in "Always use `with httpx.Client(...)`" still tells the agent to use httpx: it counts (the same
# sentence was labelled real in one skill and false in another; the engine treats both alike).
CLIENT_SHAPE_ONLY = re.compile(r"^(?:\s+(?:\.\.\.|…)(?:\s|$|[|`])|\\[.(])")


def client_reason(line: str, match: re.Match) -> str:
    if CLIENT_SHAPE_ONLY.match(line[match.end():]):
        return ""
    before, after = line[: match.start()], line[match.end():]
    if re.search(r"[\"'`]$", before) and after[:1] and after[0] == before[-1]:
        return ""
    return "used in code or a command"


def _add_clients(manifest: Manifest, line: str, location: str) -> None:
    for name, pattern in NETWORK_CLIENTS:
        matches = list(re.finditer(pattern, line, re.I))
        if not matches:
            continue
        reason = next((r for r in (client_reason(line, m) for m in matches) if r), "")
        if reason:
            manifest.add("network_clients", name, location)
            manifest.reasons.setdefault(f"network_clients|{name}", reason)
        else:
            manifest.mention("network_clients", name, location)


# Prefilters: a line that matches none of these patterns cannot match the scan that follows them, so the costly
# WRITE_CUE gate runs only on the few lines that name a startup file or a persistence mechanism.
SHELL_RC_ANY = re.compile("|".join(f"(?:{pattern})" for _, pattern in SHELL_RC), re.I)
PERSISTENCE_ANY = re.compile("|".join(f"(?:{pattern})" for _, pattern in PERSISTENCE + SHELL_RC), re.I)


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
        with warnings.catch_warnings():  # a skill's own invalid escapes ("\%") are its problem, not log noise here
            warnings.simplefilter("ignore", SyntaxWarning)
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


# ------------------------------------------------------------------ per-file cache
_FILE_CACHE: dict[tuple[str, bytes], list[tuple]] = {}
_FILE_CACHE_LIMIT = 200_000


class _RecordedReasons(dict):
    def __init__(self, ops: list[tuple]) -> None:
        super().__init__()
        self._ops = ops

    def setdefault(self, key, default=None):  # first seen wins, in file order, as on a real manifest
        self._ops.append(("reason", key, default))
        return super().setdefault(key, default)


class _Recorder:
    """Stands in for a Manifest while one file is analysed and records every call in order."""

    def __init__(self) -> None:
        self.ops: list[tuple] = []
        self.reasons = _RecordedReasons(self.ops)
        self.decode_trail: list[dict[str, str]] = []
        self.ops.append(("trail", self.decode_trail))

    def add(self, category: str, value: str, location: str) -> None:
        self.ops.append(("add", category, value, location))

    def mention(self, category: str, value: str, location: str) -> None:
        self.ops.append(("mention", category, value, location))

    def scope(self, category: str, value: str, scope: str | None) -> None:
        self.ops.append(("scope", category, value, scope))


def _replay(manifest: "Manifest", ops: list[tuple]) -> None:
    for op in ops:
        kind = op[0]
        if kind == "add":
            manifest.add(op[1], op[2], op[3])
        elif kind == "mention":
            manifest.mention(op[1], op[2], op[3])
        elif kind == "scope":
            manifest.scope(op[1], op[2], op[3])
        elif kind == "reason":
            manifest.reasons.setdefault(op[1], op[2])
        else:
            manifest.decode_trail.extend(dict(step) for step in op[1])


def _package_called_names(files: dict[str, bytes]) -> frozenset[str]:
    """Names used inside network calls anywhere in the package's scripts (a constant defined in one module and
    requested in another is still contacted)."""
    names: set[str] = set()
    for path, raw in files.items():
        if PurePosixPath(path).suffix.lower() in SCRIPT_SUFFIXES and b"\x00" not in raw[:4096]:
            names |= called_names(raw.decode("utf-8", "replace").splitlines())
    return frozenset(names)


def build_manifest(files: dict[str, bytes]) -> dict[str, Any]:
    """The capability manifest of a package. Each file is analysed on its own; its result (an ordered list of
    manifest calls) is cached by path and content, so a history of many versions re-reads only changed files.
    Replaying the calls in path order gives exactly the manifest a full scan gives."""
    result = Manifest(files=len(files))
    package_called = _package_called_names(files)
    package_digest = hashlib.sha256(" ".join(sorted(package_called)).encode()).digest()  # names hold no spaces
    for path in sorted(files):
        raw = files[path]
        is_script = PurePosixPath(path).suffix.lower() in SCRIPT_SUFFIXES
        key = (path, hashlib.sha256(raw).digest(), package_digest if is_script else b"")
        cached = _FILE_CACHE.get(key)
        if cached is not None:
            _replay(result, cached)
            continue
        manifest = _Recorder()
        failed = False
        try:
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
            anti_example, last_number, negated_list = False, 0, False
            file_copies = suffix in SCRIPT_SUFFIXES and bool(FILE_COPY.search(text))
            local_bins = set(LOCAL_BIN.findall(text)) if suffix in DOC_SUFFIXES or suffix in SCRIPT_SUFFIXES else set()
            own_env = own_env_files([text for _, text, code in lines if code], written)
            source_lines = decoded.splitlines()

            def original_line(number: int, fallback: str) -> str:  # used within this iteration only
                return source_lines[number - 1] if 0 < number <= len(source_lines) else fallback  # noqa: B023
            for index, (number, line, is_code) in enumerate(lines):
                location = f"{path}:{number}" if number <= original_lines else f"{path}:decoded"
                if number > original_lines:
                    is_code = True  # revealed payloads are always treated as code
                in_comment = is_code and number <= original_lines and bool(COMMENT_LINE.match(line)) and suffix in SCRIPT_SUFFIXES
                if in_comment:
                    continue  # a comment describes code; it does not run (license headers, notes about attacks)
                full_line = original_line(number, line)
                inline_row = suffix in DOC_SUFFIXES and is_code and line != full_line
                if suffix in DOC_SUFFIXES and number <= original_lines and not inline_row:
                    # A list under a "**✗ Don't:**" / "Avoid:" label: every item in it is something not to do.
                    if not is_code and NEGATED_LABEL.match(line):
                        negated_list = True
                    elif is_code or not line.strip() or not LIST_ITEM.match(line):
                        negated_list = False
                if inline_row and negated_list and LIST_ITEM.match(full_line):
                    continue
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
                    searched = mask_search_patterns(line) if is_code else line
                    for match in URL.finditer(line):
                        host = match.group(1).lower().strip("[]")
                        if searched[match.start()] != line[match.start()]:
                            manifest.mention("network_hosts", host, location)
                            continue  # an address inside a search pattern is looked for, not contacted
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
                                reason = contact_reason(line, match.start(), path, neighbours, previous, called, package_called)
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
                                          else contact_reason(line, ip_match.start(), path, neighbours, previous, called, package_called))
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
                    if PERSISTENCE_ANY.search(line) and WRITE_CUE.search(line) and not TABLE_ROW.match(original_line(number, line)):
                        _scan_patterns(manifest, "persistence", PERSISTENCE + SHELL_RC, line, location)
                    continue
                command_line = all_spans = line
                if inline_row:
                    # An inline-code row from Markdown prose. Drop spans the sentence negates ("Never run its setup
                    # scripts or `curl | sh`"), and treat a single bare word (`curl`, `os.environ`, `httpx.Client`,
                    # `~/Library/LaunchAgents` listed as an indicator) as a mention: a command has arguments.
                    # A sentence wrapped across lines ("..., never by\n`rm -rf`."): read the line before as part of it.
                    above = original_line(number - 1, "").strip() if number > 1 else ""
                    carried = above + " " if above and not re.search(r"[.!?:]\s*$|^#", above) and not LIST_ITEM.match(full_line) else ""
                    spans = [m.group(1) for m in INLINE_CODE.finditer(full_line)
                             if not NEGATED.search((carried + full_line[: m.start()])[-60:])]
                    all_spans = " ; ".join(spans)
                    command_line = " ; ".join(s for s in spans if len(s.split()) > 1)
                command_line, all_spans = mask_search_patterns(command_line), mask_search_patterns(all_spans)
                alternation_free = ALTERNATION.sub(" ", command_line)  # "curl|wget|nc", "{zsh|bash|powershell}" are lists
                _add_clients(manifest, alternation_free, location)
                for name, pattern in PROCESS_EXEC:
                    found = re.search(pattern, command_line if name == "pipe-to-shell" else alternation_free, re.I)
                    if not found:
                        continue
                    at = line.find(found.group(0)) if found.group(0) in line else -1
                    if name == "powershell" and SETTING_SHELL.search(alternation_free[: found.start()]):
                        continue  # `shell: pwsh` in a workflow names the shell of a CI step
                    if LOCATE_BEFORE.search(alternation_free[: found.start()]):
                        manifest.mention("process_execution", name, location)
                        continue  # `Get-Command pwsh`, `which bash`: finding where a program is, not running it
                    if PLACEHOLDER_ARG.match(alternation_free[found.end():]):
                        manifest.mention("process_execution", name, location)
                        continue  # `bash -c 'TRIGGER'`, `sh -c <cmd>`: the shape of a command, its argument a slot
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
                if SHELL_RC_ANY.search(command_line) and WRITE_CUE.search(command_line):
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
                        joined = joined_path_line(line) if suffix in SCRIPT_SUFFIXES else ""
                        if joined:
                            _add_config_writes(manifest, joined, location, prose=False, written=written)
                            install_dir = AGENT_INSTALL_DIR.search(joined)
                            if install_dir and file_copies:
                                # An agent skills/commands folder built in a script that copies or writes files: the
                                # script installs into the agent's configuration (distilly: join(home, ".claude", "skills")).
                                value = ".claude/commands" if ".claude/" in install_dir.group(0) else next(
                                    (n for n, pat in AGENT_CONFIG if re.search(pat, joined)), install_dir.group(0))
                                manifest.add("agent_config_writes", value, location)
                                manifest.reasons.setdefault(f"agent_config_writes|{value}", "an install target in a script that copies files")
                        if suffix in DOC_SUFFIXES and YAML_TEXT_VALUE.match(line):
                            # A text value in front matter or YAML in docs ("short-description: Update AGENTS.md with
                            # design system rules") is a sentence: read it as prose.
                            _add_config_writes(manifest, line, location, prose=True)
                for match in ENV_READ.finditer(all_spans):
                    name = next(g for g in match.groups() if g).upper()
                    if not is_secret_env(name):
                        continue  # $env:APPDATA is a folder, AGENT_ID an identifier, PORT configuration: not secrets
                    if re.match(r"\s*[\])]?\s*=(?!=)", all_spans[match.end():]):
                        manifest.mention("credential_access", "env:" + name, location)
                        continue  # os.environ["TOKEN"] = value SETS the variable; nothing is read
                    manifest.add("credential_access", "env:" + name, location)
                if "env" in command_line and ENV_ALL.search(command_line):  # every ENV_ALL branch contains "env"
                    if not ENV_INHERIT.search(command_line) or ENV_OUT.search(command_line) or ENV_ALL.search(ENV_INHERIT.sub(" ", command_line)):
                        manifest.add("credential_access", "env:<all>", location)
                    else:
                        # env={**os.environ, "HOME": h}: the child gets the environment every child gets by default.
                        # Nothing is read or enumerated; a line that also dumps, prints, sends or loops over it stays a read.
                        manifest.mention("credential_access", "env:<all>", location)
                if is_test:
                    continue  # an install command inside a test's string data is test input, not something run
                searched = mask_search_patterns(line)
                for match in INSTALL.finditer(line):
                    if searched[match.start()] != line[match.start()]:
                        continue  # `grep -E 'go (install|run) '`: an install command searched for, not run
                    full = original_line(number, line)
                    command = " ".join(match.group(0).split()[:2])  # e.g. "npm install", findable in the original line
                    if NEGATED.search(full[: max(0, full.find(command))][-40:]):
                        continue  # "do not run `npm install` first" is the opposite of an install
                    if inline_row and (CHANGELOG_FILE.search(path) or describes_span(full, command)):
                        continue  # "`npx skills add` copies the folder": the command is described, not instructed
                    groups = [g for g in match.groups() if g]
                    tool = "uv" if match.group(3) else re.sub(r"\s+", " ", groups[0]).lower()
                    tool = TOOL_ALIASES.get(tool, tool)
                    package = groups[-1].strip(".,;:)\"'`").rstrip("@")  # "@ag-ui/client@<pinned version>" -> the name
                    if package and not package.startswith("-") and package.lower() not in STOP_PACKAGES and not PLACEHOLDER_TOKEN.search(package):
                        if tool in {"npx", "bunx", "pnpm dlx"} and package in local_bins:
                            manifest.mention("package_installs", f"{tool}:{package}", location)
                            continue  # runs a bin the file says is already installed; nothing is fetched
                        manifest.add("package_installs", f"{tool}:{package}", location)
                        if tool in MULTI_INSTALL_TOOLS and "://" not in package:
                            for extra in _more_packages(line[match.end():]):
                                manifest.add("package_installs", f"{tool}:{extra}", location)
        except BaseException:
            failed = True
            raise
        finally:
            if not failed:
                if len(_FILE_CACHE) >= _FILE_CACHE_LIMIT:
                    _FILE_CACHE.clear()
                _FILE_CACHE[key] = manifest.ops
                _replay(result, manifest.ops)
    from skillproof.engines.confidence import add_blocks  # block kind and stated purpose, read by triage's confidence

    out = result.to_dict()
    add_blocks(out, files)
    invoked = invoked_test_named(files)
    if invoked:
        out["invoked_test_named"] = invoked
    return out


def invoked_test_named(files: dict[str, bytes]) -> list[str]:
    """Files named like tests (test_detectors.py, selftest.py) outside a tests folder that another, non-test file of
    the package names: utilities the skill runs, not tests. Labelled held-outs 1-9: 3 real items were capped at note
    by their name alone, 0 false ones would be raised (a file inside a tests folder stays a test however it is named)."""
    out = []
    for path in files:
        name = PurePosixPath(path).name
        if TEST_PATH.search(path) or not TEST_NAME.match(name):
            continue
        named = re.compile(r"(?<![\w.-])" + re.escape(name) + r"(?![\w-])")
        for other, raw in files.items():
            if other == path or TEST_PATH.search(other) or TEST_NAME.match(PurePosixPath(other).name):
                continue
            if named.search(raw.decode("utf-8", "replace")):
                out.append(path)
                break
    return sorted(out)
