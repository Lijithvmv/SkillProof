"""Every setting SkillProof reads, in one place, typed and validated.

Values come from the environment; `skillproof serve --config file.toml` writes the file's values into the environment
first (service.apply_config), so the same names apply to the API, the CLI and the workers. `settings()` reads them at
call time, so a test or a config file that sets a variable is seen immediately. `problems()` lists what is wrong with
a configuration; the service refuses to start in production while any problem remains.

| Variable | Setting | Meaning |
|---|---|---|
| SKILLPROOF_ENV | environment | `development` (default) or `production` |
| SKILLPROOF_DATABASE_URL | database_url | PostgreSQL URL (one database, tenant row-level security) |
| SKILLPROOF_DATA_DIR | data_dir | folder of SQLite files (one machine); used when no database URL is set |
| SKILLPROOF_DB_POOL_SIZE | db_pool_size | PostgreSQL connections per store (default 10) |
| SKILLPROOF_SCHEMA | schema_mode | `apply` pending migrations at start (default) or `verify` and refuse |
| SKILLPROOF_LOG_LEVEL | log_level | default `info` |
| SKILLPROOF_AUTH_MODE | auth_mode | `local` (development identity headers) or `oidc` |
| SKILLPROOF_OIDC_* | oidc | issuer, audience, JWKS URL, client id, scope, role/tenant claims, endpoints, leeway, JWKS timeout, agent client ids (`AGENT_CLIENTS`, comma-separated) |
| SKILLPROOF_OLLAMA_URL | ollama_url | local model server (loopback) |
| SKILLPROOF_MIN_LOAD_RATE / SKILLPROOF_MAX_FALSE_LOAD_RATE | min_load_rate, max_false_load_rate | load-rate gate: least share of relevant requests that pick the skill (0.5), most share of unrelated ones (0.2) |
| SKILLPROOF_EVAL_MODEL / _DRAFT_MODEL / _TASKS / _REPEATS | evaluation | evaluation jobs; off when no model is set |
| SKILLPROOF_SECOND_OPINION_MODEL / _URL | second_opinion | local-model second opinion on risk items; off when no model is set |
| SKILLPROOF_PROVIDER, SKILLPROOF_MODEL, SKILLPROOF_GRADER_MODEL | pilot | defaults for the `pilot` and `grader-check` commands |

Two values are deliberately read where they are used, not here: `OPENAI_API_KEY` (a secret, read only by the OpenAI
adapter) and the fleet reporter's bearer token (from the variable named by `fleet-report --token-env`).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _get(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _int(name: str, default: int) -> int:
    raw = _get(name)
    try:
        return int(raw) if raw else default
    except ValueError:
        return -1  # reported by problems()


def _float(name: str, default: float) -> float:
    raw = _get(name)
    try:
        return float(raw) if raw else default
    except ValueError:
        return -1.0


@dataclass(frozen=True)
class OIDC:
    issuer: str = ""
    audience: str = ""
    jwks_url: str = ""
    client_id: str = ""
    scope: str = "openid profile"
    role_claim: str = "skillproof_role"
    tenant_claim: str = "tenant_id"
    authorization_url: str = ""
    token_url: str = ""
    end_session_url: str = ""
    leeway_seconds: int = 30
    jwks_timeout_seconds: float = 5.0
    agent_clients: tuple[str, ...] = ()  # OAuth client ids issued to agents: their tokens are agent identities

    @property
    def configured(self) -> bool:
        return bool(self.issuer or self.audience or self.jwks_url)


@dataclass(frozen=True)
class Evaluation:
    model: str = ""
    draft_model: str = ""
    tasks: int = 6
    repeats: int = 2

    @property
    def enabled(self) -> bool:
        return bool(self.model)


@dataclass(frozen=True)
class Settings:
    environment: str = "development"
    database_url: str = ""
    data_dir: str = ""
    db_pool_size: int = 10
    schema_mode: str = "apply"
    log_level: str = "info"
    auth_mode: str = "local"
    oidc: OIDC = field(default_factory=OIDC)
    ollama_url: str = "http://127.0.0.1:11434"
    evaluation: Evaluation = field(default_factory=Evaluation)
    second_opinion_model: str = ""
    second_opinion_url: str = "http://127.0.0.1:11434"
    pilot_provider: str = "openai"
    pilot_model: str = ""
    pilot_grader_model: str = ""
    # Load-rate gate (a version citing a load-rate run): the least share of relevant requests that must pick the skill,
    # and the most share of unrelated requests that may. Defaults are starting points, not validated thresholds.
    min_load_rate: float = 0.5
    max_false_load_rate: float = 0.2

    @property
    def production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def storage_configured(self) -> bool:
        return bool(self.database_url or self.data_dir)


def settings() -> Settings:
    """The configuration in force now."""
    return Settings(
        environment=_get("SKILLPROOF_ENV", "development").lower() or "development",
        database_url=_get("SKILLPROOF_DATABASE_URL"),
        data_dir=_get("SKILLPROOF_DATA_DIR"),
        db_pool_size=_int("SKILLPROOF_DB_POOL_SIZE", 10),
        schema_mode=_get("SKILLPROOF_SCHEMA", "apply").lower() or "apply",
        log_level=_get("SKILLPROOF_LOG_LEVEL", "info").lower() or "info",
        auth_mode=_get("SKILLPROOF_AUTH_MODE", "local").lower() or "local",
        oidc=OIDC(
            issuer=_get("SKILLPROOF_OIDC_ISSUER"), audience=_get("SKILLPROOF_OIDC_AUDIENCE"), jwks_url=_get("SKILLPROOF_OIDC_JWKS_URL"),
            client_id=_get("SKILLPROOF_OIDC_CLIENT_ID"), scope=_get("SKILLPROOF_OIDC_SCOPE", "openid profile") or "openid profile",
            role_claim=_get("SKILLPROOF_OIDC_ROLE_CLAIM", "skillproof_role") or "skillproof_role",
            tenant_claim=_get("SKILLPROOF_OIDC_TENANT_CLAIM", "tenant_id") or "tenant_id",
            authorization_url=_get("SKILLPROOF_OIDC_AUTHORIZATION_URL"), token_url=_get("SKILLPROOF_OIDC_TOKEN_URL"),
            end_session_url=_get("SKILLPROOF_OIDC_END_SESSION_URL"),
            leeway_seconds=_int("SKILLPROOF_OIDC_LEEWAY_SECONDS", 30), jwks_timeout_seconds=_float("SKILLPROOF_OIDC_JWKS_TIMEOUT_SECONDS", 5.0),
            agent_clients=tuple(c.strip() for c in (_get("SKILLPROOF_OIDC_AGENT_CLIENTS") or "").split(",") if c.strip())),
        ollama_url=_get("SKILLPROOF_OLLAMA_URL", "http://127.0.0.1:11434") or "http://127.0.0.1:11434",
        evaluation=Evaluation(model=_get("SKILLPROOF_EVAL_MODEL"), draft_model=_get("SKILLPROOF_EVAL_DRAFT_MODEL"),
                              tasks=_int("SKILLPROOF_EVAL_TASKS", 6), repeats=_int("SKILLPROOF_EVAL_REPEATS", 2)),
        second_opinion_model=_get("SKILLPROOF_SECOND_OPINION_MODEL"),
        second_opinion_url=_get("SKILLPROOF_SECOND_OPINION_URL", "http://127.0.0.1:11434") or "http://127.0.0.1:11434",
        pilot_provider=_get("SKILLPROOF_PROVIDER", "openai") or "openai",
        pilot_model=_get("SKILLPROOF_MODEL") or _get("SKILLPROOF_OPENAI_MODEL"),
        pilot_grader_model=_get("SKILLPROOF_GRADER_MODEL") or _get("SKILLPROOF_OPENAI_GRADER_MODEL"),
        min_load_rate=_float("SKILLPROOF_MIN_LOAD_RATE", 0.5),
        max_false_load_rate=_float("SKILLPROOF_MAX_FALSE_LOAD_RATE", 0.2),
    )


def problems(config: Settings | None = None) -> list[str]:
    """What is wrong with a configuration, in words an operator can act on. Empty when it is usable."""
    s = config or settings()
    found = []
    if s.environment not in {"development", "production"}:
        found.append(f"SKILLPROOF_ENV must be development or production, not {s.environment!r}")
    if not (0 <= s.min_load_rate <= 1 and 0 <= s.max_false_load_rate <= 1):
        found.append("SKILLPROOF_MIN_LOAD_RATE and SKILLPROOF_MAX_FALSE_LOAD_RATE must be between 0 and 1")
    if s.auth_mode not in {"local", "oidc"}:
        found.append(f"SKILLPROOF_AUTH_MODE must be local or oidc, not {s.auth_mode!r}")
    if s.production and s.auth_mode != "oidc":
        found.append("production requires SKILLPROOF_AUTH_MODE=oidc")
    if s.auth_mode == "oidc" and not (s.oidc.issuer and s.oidc.audience and s.oidc.jwks_url):
        found.append("OIDC needs SKILLPROOF_OIDC_ISSUER, SKILLPROOF_OIDC_AUDIENCE and SKILLPROOF_OIDC_JWKS_URL")
    if s.auth_mode == "local" and s.oidc.configured:
        found.append("OIDC settings are present while SKILLPROOF_AUTH_MODE is local; set SKILLPROOF_AUTH_MODE=oidc")
    if s.database_url and not s.database_url.startswith(("postgresql://", "postgres://")):
        found.append("SKILLPROOF_DATABASE_URL must be a postgresql:// URL")
    if s.schema_mode not in {"apply", "verify"}:
        found.append(f"SKILLPROOF_SCHEMA must be apply or verify, not {s.schema_mode!r}")
    if s.db_pool_size < 2:
        found.append("SKILLPROOF_DB_POOL_SIZE must be a whole number of at least 2")
    if s.log_level not in {"debug", "info", "warning", "error"}:
        found.append(f"SKILLPROOF_LOG_LEVEL must be debug, info, warning or error, not {s.log_level!r}")
    if s.evaluation.tasks < 1 or s.evaluation.repeats < 1:
        found.append("SKILLPROOF_EVAL_TASKS and SKILLPROOF_EVAL_REPEATS must be whole numbers of at least 1")
    if s.oidc.leeway_seconds < 0 or s.oidc.jwks_timeout_seconds <= 0:
        found.append("SKILLPROOF_OIDC_LEEWAY_SECONDS and SKILLPROOF_OIDC_JWKS_TIMEOUT_SECONDS must be non-negative numbers")
    return found
