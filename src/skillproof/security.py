"""Static security triage for skill package text and file names.

This module never executes package content and intentionally redacts matched
secret values from evidence.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any


RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("PROMPT_INJECTION_DIRECTIVE", "high", "Text attempts to override higher-priority instructions or reveal hidden prompts.", re.compile(r"\b(ignore|disregard|bypass)\s+(all\s+)?(previous|prior|system|developer)\s+instructions\b|\b(reveal|print|show|expose)\s+(the\s+)?(system|developer|hidden)\s+prompt\b", re.I)),
    ("DATA_EXFILTRATION_INSTRUCTION", "critical", "Text instructs disclosure or transfer of credentials, environment variables, or private data.", re.compile(r"\b(upload|send|post|exfiltrate|transmit|email)\b.{0,100}\b(environment variables?|secrets?|credentials?|api keys?|private keys?|tokens?)\b|\b(environment variables?|secrets?|credentials?)\b.{0,100}\b(upload|send|post|exfiltrate|transmit)\b", re.I)),
    ("UNSAFE_SHELL_COMMAND", "high", "Instruction contains a shell pattern commonly associated with unsafe or destructive execution.", re.compile(r"\b(?:sudo\s+)?rm\s+-[a-z]*r[a-z]*f\b|\bchmod\s+0?777\b|\bcurl\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:bash|sh)\b|\bwget\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:bash|sh)\b|\bpowershell(?:\.exe)?\s+[^\n]{0,100}-(?:enc|encodedcommand)\b", re.I)),
    ("UNSAFE_DEPENDENCY_SOURCE", "high", "Dependency installation references an untrusted URL or VCS source; verify provenance and pinning.", re.compile(r"\b(?:pip|pip3)\s+install\s+(?:https?://|git\+)|\bnpm\s+install\s+(?:https?://|git\+)|\b(?:curl|wget)\s+https?://", re.I)),
    ("EXCESSIVE_PRIVILEGE_REQUEST", "medium", "Instructions request broad privileges or disable a security control.", re.compile(r"\b(grant|allow|enable)\s+(?:it\s+)?(?:full|unrestricted|administrator|root)\s+(?:access|permission|privileges?)\b|\b(disable|turn off|bypass)\s+(?:all\s+)?(?:security|approval|confirmation|permission)\s+(?:checks?|prompts?|controls?)\b", re.I)),
    ("CREDENTIAL_EXPOSURE", "critical", "Text appears to contain a credential or private key. The matched value is redacted.", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b|\b(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9/+=_-]{16,}", re.I)),
]

SECRET_NAMES = re.compile(r"(?:^|/)(?:\.env(?:\..*)?|id_rsa|id_ed25519|credentials(?:\.json)?|secrets?\.ya?ml|.*\.(?:pem|key|p12|pfx))$", re.I)
URL = re.compile(r"https?://[^\s)\]>\"']+", re.I)


def scan_security(files: dict[str, str]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    for path in sorted(files):
        if SECRET_NAMES.search(path.replace("\\", "/")):
            findings.append({"code": "CREDENTIAL_FILE_BUNDLED", "severity": "high", "message": "Package includes a filename commonly used for credentials or private keys.", "evidence": path})
        for line_no, line in enumerate(files[path].splitlines(), 1):
            for code, severity, message, pattern in RULES:
                if pattern.search(line):
                    evidence = f"{path}:{line_no} (matched {code.lower().replace('_', ' ')})"
                    findings.append({"code": code, "severity": severity, "message": message, "evidence": evidence})
            for target in URL.findall(line):
                findings.append({"code": "EXTERNAL_REFERENCE_REVIEW", "severity": "info", "message": "External URL found; review destination and the trust of fetched content.", "evidence": f"{path}:{line_no} ({target[:120]})"})
    unique = {(item["code"], item["evidence"]): item for item in findings}
    findings = sorted(unique.values(), key=lambda item: (item["severity"], item["code"], item["evidence"]))
    for item in findings:
        # A static match is a lead, not a verdict. It stays needs_validation until a reviewer records
        # confirmed or rejected with a reason (see record_validation).
        item["finding_id"] = hashlib.sha256(f"{item['code']}|{item['evidence']}".encode("utf-8")).hexdigest()[:12]
        item["status"] = "needs_validation"
    weights = {"critical": 35, "high": 20, "medium": 10, "low": 5, "info": 0}
    score = max(0, 100 - sum(weights[item["severity"]] for item in findings))
    return {
        "method": "static_pattern_scan",
        "security_score": score,
        "status": "review_required" if any(item["severity"] in {"critical", "high", "medium"} for item in findings) else "no_static_findings",
        "findings": findings,
        "limitations": "A static pattern scan can produce false positives and miss novel or contextual attacks. No package code was executed; this is not a security certification.",
    }


STATUSES = {"needs_validation", "confirmed", "rejected"}
BLOCKING = {"critical", "high"}


def record_validation(report: dict[str, Any], decisions: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply reviewer decisions to a security report's findings.

    Each decision names a finding_id, a status of confirmed or rejected, a reviewer, and a reason. The reason is
    required: it records what the reviewer checked when trying to disprove the finding, so a "rejected" is an
    argument, not a shrug. Findings without a decision keep needs_validation.
    """
    findings = [dict(item) for item in report.get("findings", [])]
    by_id = {item.get("finding_id"): item for item in findings}
    for decision in decisions:
        finding_id, status = decision.get("finding_id"), decision.get("status")
        if finding_id not in by_id:
            raise ValueError(f"Unknown finding_id: {finding_id!r}")
        if status not in {"confirmed", "rejected"}:
            raise ValueError("Decision status must be confirmed or rejected")
        reviewer, reason = str(decision.get("reviewer") or "").strip(), str(decision.get("reason") or "").strip()
        if not reviewer or len(reason) < 10:
            raise ValueError(f"Decision for {finding_id} needs a reviewer and a reason of at least 10 characters")
        by_id[finding_id].update(status=status, reviewer=reviewer, reason=reason[:2000])
    counts = {status: sum(item.get("status") == status for item in findings) for status in sorted(STATUSES)}
    confirmed_blocking = [item["finding_id"] for item in findings if item.get("status") == "confirmed" and item["severity"] in BLOCKING]
    open_review = [item["finding_id"] for item in findings if item.get("status") == "needs_validation" and item["severity"] not in {"low", "info"}]
    decision = "blocked" if confirmed_blocking else "review_required" if open_review else "cleared"
    return {
        "method": "static_findings_with_recorded_validation",
        "decision": decision,
        "status_counts": counts,
        "confirmed_blocking": confirmed_blocking,
        "awaiting_validation": open_review,
        "findings": findings,
        "limitations": "Decisions are as good as the reviewer's check. Cleared means no medium-or-higher finding is open or confirmed; it is not a security certification.",
    }
