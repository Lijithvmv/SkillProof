"""One settings module. Decision changed: a production service with an unsafe or inconsistent configuration refuses to
start and says why, instead of failing later or running with development identity."""
import pytest

from skillproof.config import problems, settings
from skillproof.service import ServiceError, serve


def test_settings_are_read_in_one_place_with_defaults(monkeypatch):
    for name in ("SKILLPROOF_ENV", "SKILLPROOF_EVAL_MODEL", "SKILLPROOF_DB_POOL_SIZE"):
        monkeypatch.delenv(name, raising=False)
    current = settings()
    assert current.environment == "development" and not current.production and current.db_pool_size == 10
    assert not current.evaluation.enabled
    monkeypatch.setenv("SKILLPROOF_EVAL_MODEL", "m")
    assert settings().evaluation.enabled and settings().evaluation.tasks == 6


def test_problems_name_what_is_wrong(monkeypatch):
    monkeypatch.setenv("SKILLPROOF_ENV", "production")
    monkeypatch.setenv("SKILLPROOF_AUTH_MODE", "local")
    monkeypatch.setenv("SKILLPROOF_DB_POOL_SIZE", "one")
    monkeypatch.setenv("SKILLPROOF_DATABASE_URL", "mysql://x")
    found = problems()
    assert "production requires SKILLPROOF_AUTH_MODE=oidc" in found
    assert any("POOL_SIZE" in p for p in found) and any("postgresql://" in p for p in found)


def test_production_service_refuses_to_start_with_problems(monkeypatch, tmp_path):
    # serve() writes the configuration into the environment; register every variable it touches so it is restored.
    from skillproof.service import ENV_KEYS

    for name in set(ENV_KEYS.values()):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.setenv("SKILLPROOF_DB_POOL_SIZE", "1")
    config = {"server": {"environment": "production", "host": "127.0.0.1", "port": 1}, "storage": {"data_dir": str(tmp_path)},
              "auth": {"mode": "local"}}
    with pytest.raises(ServiceError, match="refusing to start in production"):
        serve(config)
