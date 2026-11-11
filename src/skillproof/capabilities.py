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

import base64
import binascii
import re
import stat
import unicodedata
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any

from skillproof.ingestion import MAX_FILE_SIZE, MAX_FILES, MAX_TOTAL_SIZE, PackageError

MANIFEST_VERSION = "0.1.0"

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
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FETCH_CUE = re.compile(r"\b(curl|wget|fetch|download|upload|requests?\.\w+|webhook|send (?:it |the \w+ )?to|post (?:it |the \w+ )?to|invoke-webrequest|iwr|irm)\b", re.I)
# A namespace or schema URI is an identifier, not an endpoint (e.g. xmlns="http://www.w3.org/2000/svg").
NAMESPACE_CONTEXT = re.compile(r"(?:xmlns(?::[\w.-]+)?|schemaLocation|targetNamespace|namespace|\$schema|\$id|@context|\b\w*_NS)[\"']?\s*[=:]\s*[\"']?[^\"'\s]*$", re.I)
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
    ("fetch", r"\bfetch\(\s*['\"`]?https?:"), ("axios", r"\baxios\b"), ("http.client", r"\bhttp\.client\b"),
    ("socket", r"\bsocket\.(?:socket|create_connection)\b"), ("netcat", r"\b(?:nc|ncat|netcat)\s+-"),
    ("invoke-webrequest", r"\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"),
]
PROCESS_EXEC = [
    ("subprocess", r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\b"), ("os.system", r"\bos\.(?:system|popen|exec\w*)\("),
    ("eval", r"(?<![\w.])eval\("), ("exec", r"(?<![\w.])exec\("), ("child_process", r"\bchild_process\b|\bexecSync\(|\bspawnSync?\("),
    ("shell -c", r"\b(?:bash|sh|zsh)\s+-c\b"), ("pipe-to-shell", r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|base64\s+-d|base64\s+--decode|cat|echo|printf)\b[^|\n]*(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|node|iex|Invoke-Expression)\b"),
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
    ("systemd", r"\bsystemctl\s+(?:enable|start)\b|/etc/systemd|\.service\b"), ("launchd", r"\blaunchctl\b|LaunchAgents|LaunchDaemons"),
    ("windows run key", r"CurrentVersion\\+Run\b"), ("scheduled task", r"\bschtasks\b|Register-ScheduledTask"),
    ("startup folder", r"Start Menu\\+Programs\\+Startup"),
]
CREDENTIALS = [
    ("ssh keys", r"~?/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b"), ("aws credentials", r"\.aws[/\\]credentials|\bAWS_SECRET_ACCESS_KEY\b"),
    ("netrc", r"\.netrc\b"), ("npmrc/pypirc", r"\.npmrc\b|\.pypirc\b"), ("keychain", r"\bsecurity\s+find-(?:generic|internet)-password\b|\bkeyring\.get_password\b"),
    ("gh token", r"\bgh\s+auth\s+token\b"), ("browser data", r"Login Data|cookies\.sqlite|Local State"),
    (".env file", r"(?<![\w.])\.env\b(?!\.example)"),
]
ENV_READ = re.compile(r"os\.environ(?:\.get)?[\[(]\s*['\"]([A-Z][A-Z0-9_]{2,})['\"]|os\.getenv\(\s*['\"]([A-Z][A-Z0-9_]{2,})['\"]|process\.env\.([A-Z][A-Z0-9_]{2,})|\$env:([A-Z][A-Z0-9_]{2,})", re.I)
ENV_ALL = re.compile(r"\bos\.environ\b(?![\[.(])|\bprocess\.env\b(?![.\[])|\bprintenv\b|\benv\s*\|")
INSTALL = re.compile(
    r"\b(pip3?|uv\s+pip|python3?\s+-m\s+pip)\s+install\s+(?:-[\w-]+\s+)*([A-Za-z0-9_.\-\[\]=<>~!+:/@]+)"
    r"|\buv\s+add\s+([A-Za-z0-9_.\-]+)"
    r"|\b(npm)\s+(?:install|i|add)\s+(?:-[\w-]+\s+)*(@?[A-Za-z0-9_.\-/@^~:+]+)"
    r"|\b(npx|pnpm\s+dlx|bunx)\s+(?:-[\w-]+\s+)*(@?[A-Za-z0-9_.\-/@^~:+]+)"
    r"|\b(pnpm|yarn|bun)\s+add\s+(?:-[\w-]+\s+)*(@?[A-Za-z0-9_.\-/@^~:+]+)"
    r"|\b(go)\s+(?:install|get)\s+([A-Za-z0-9_.\-/@]+)"
    r"|\b(cargo|gem|brew)\s+install\s+(?:-[\w-]+\s+)*([A-Za-z0-9_.\-/@]+)"
    r"|\b(apt(?:-get)?|yum|dnf|apk)\s+(?:install|add)\s+(?:-[\w-]+\s+)*([A-Za-z0-9_.\-+]+)",
    re.I,
)
DESTRUCTIVE = [
    ("rm -rf", r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r"), ("rmtree", r"\bshutil\.rmtree\("), ("Remove-Item -Recurse", r"Remove-Item\b[^\n]*-Recurse"),
    ("format/mkfs", r"\bmkfs(?:\.\w+)?\b|\bformat\s+[a-z]:"), ("git push --force", r"\bgit\s+push\b[^\n]*(?:--force|-f)\b"),
    ("dd", r"\bdd\s+if="),
]
WRITE_CUE = re.compile(r"(?:>>?|\btee\b|\bwrite|\bappend|\bopen\([^)]*['\"][wa]|\bcp\b|\bmv\b|\bcopy|\bmodify|\bedit|\badd (?:this|the following|a line)|\binsert|\bupdate|\bWriteAllText|\bSet-Content|\bAdd-Content|\bOut-File|\bwriteFile|\bappendFile|\becho\b)", re.I)

CATEGORIES = (
    "network_hosts", "network_clients", "process_execution", "agent_config_writes", "persistence",
    "credential_access", "package_installs", "destructive_operations", "bundled_binaries", "hiding_techniques",
)


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
    rows, fenced = [], False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced:
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
    groups = (NETWORK_CLIENTS, PROCESS_EXEC, PERSISTENCE, CREDENTIALS, DESTRUCTIVE, AGENT_CONFIG)
    return any(re.search(pattern, text, re.I) for group in groups for _, pattern in group)


def build_manifest(files: dict[str, bytes]) -> dict[str, Any]:
    manifest = Manifest(files=len(files))
    for path in sorted(files):
        raw = files[path]
        suffix = PurePosixPath(path).suffix.lower()
        is_binary = suffix in BINARY_SUFFIXES or raw[:4] in {b"\x7fELF", b"MZ\x90\x00"} or raw[:2] == b"MZ" or b"\x00" in raw[:4096]
        if is_binary and suffix not in TEXT_SUFFIXES:
            manifest.add("bundled_binaries", path, path)
            continue
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            manifest.add("bundled_binaries", path, path)
            continue
        trail_start = len(manifest.decode_trail)
        decoded = decode_text(text, path, manifest.decode_trail)
        for step in manifest.decode_trail[trail_start:]:
            # Hiding matters when it hides something: count a technique only if what it revealed is itself a
            # capability (a host, a command, a config path...). Ordinary "a" + "b" joins are not disguise.
            if _reveals_capability(step["after"]):
                step["revealed_capability"] = "yes"
                manifest.add("hiding_techniques", step["technique"], path)
        original_lines = len(text.splitlines())
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
            cue = is_code or bool(FETCH_CUE.search(line))
            if cue and PurePosixPath(path).name.lower() not in LOCKFILES:
                for match in URL.finditer(line):
                    host = match.group(1).lower().strip("[]")
                    if NAMESPACE_CONTEXT.search(line[: match.start()]) or NOT_EXTERNAL.match(host) or host in IDENTIFIER_HOSTS:
                        continue
                    manifest.add("network_hosts", host, location)
                if is_code:
                    for ip in IPV4.findall(line):
                        if all(0 <= int(octet) <= 255 for octet in ip.split(".")) and not ip.startswith(("0.", "127.")):
                            manifest.add("network_hosts", ip, location)
            if not is_code:
                continue
            _scan_patterns(manifest, "network_clients", NETWORK_CLIENTS, line, location)
            _scan_patterns(manifest, "process_execution", PROCESS_EXEC, line, location)
            _scan_patterns(manifest, "persistence", PERSISTENCE, line, location)
            _scan_patterns(manifest, "credential_access", CREDENTIALS, line, location)
            _scan_patterns(manifest, "destructive_operations", DESTRUCTIVE, line, location)
            window = " ".join(row[1] for row in lines[max(0, index - 2): index + 3])
            if WRITE_CUE.search(window):
                _scan_patterns(manifest, "agent_config_writes", AGENT_CONFIG, line, location)
            for match in ENV_READ.finditer(line):
                manifest.add("credential_access", "env:" + next(g for g in match.groups() if g).upper(), location)
            if ENV_ALL.search(line):
                manifest.add("credential_access", "env:<all>", location)
            for match in INSTALL.finditer(line):
                full = original_line(number, line)
                command = " ".join(match.group(0).split()[:2])  # e.g. "npm install", findable in the original line
                if NEGATED.search(full[: max(0, full.find(command))][-40:]):
                    continue  # "do not run `npm install` first" is the opposite of an install
                groups = [g for g in match.groups() if g]
                tool = "uv" if match.group(3) else re.sub(r"\s+", " ", groups[0]).lower()
                package = groups[-1].strip(".,;:)\"'`")
                if package and not package.startswith("-"):
                    manifest.add("package_installs", f"{tool}:{package}", location)
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
