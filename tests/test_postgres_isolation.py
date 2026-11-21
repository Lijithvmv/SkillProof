"""PostgreSQL enforces tenant isolation itself (row-level security), not only the application's WHERE clauses."""
import pytest

from conftest import PG_URL
from skillproof.registry import SkillRegistry
from test_registry import assurance_report, skill_report

pytestmark = pytest.mark.skipif(not PG_URL, reason="set SKILLPROOF_TEST_PG_URL to run the PostgreSQL checks")


def test_rows_of_another_tenant_are_invisible_and_unwritable(tmp_path):
    registry = SkillRegistry(tmp_path / "registry.db")  # redirected to a fresh PostgreSQL schema by conftest
    assert registry.db.postgres
    registry.register("tenant-a", skill_report("alpha", "a"), assurance_report(), actor_id="alice")
    registry.register("tenant-b", skill_report("beta", "b"), assurance_report(), actor_id="bob")

    # A query with no tenant filter at all still sees only the transaction's tenant.
    with registry.db.transaction("tenant-a") as db:
        names = {row["skill_name"] for row in db.execute("SELECT skill_name FROM skill_versions").fetchall()}
        events = {row["tenant_id"] for row in db.execute("SELECT tenant_id FROM registry_events").fetchall()}
    assert names == {"alpha"} and events == {"tenant-a"}

    # Without a tenant, nothing is visible.
    with registry.db.transaction(None) as db:
        assert db.execute("SELECT count(*) AS n FROM skill_versions").fetchone()["n"] == 0

    # Writing a row that belongs to another tenant is refused by the policy.
    with pytest.raises(Exception, match="row-level security"):
        with registry.db.transaction("tenant-a", write=True) as db:
            db.execute("UPDATE skill_versions SET tenant_id='tenant-b' WHERE skill_name='alpha'")
    with pytest.raises(Exception, match="row-level security"):
        with registry.db.transaction("tenant-a", write=True) as db:
            db.execute(
                "INSERT INTO registry_events (version_id, tenant_id, actor_id, action, detail, occurred_at) "
                "SELECT version_id, 'tenant-b', 'mallory', 'x', 'x', 'x' FROM skill_versions LIMIT 1")

    # The application's role cannot switch the protection off.
    with registry.db.transaction("tenant-a") as db:
        role = db.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
    assert role["rolsuper"] is False and role["rolbypassrls"] is False
    registry.close()


def test_concurrent_writers_from_many_threads_all_land(tmp_path):
    # Decision: the service can take parallel requests without one request's statements landing in another's
    # transaction (the shared-connection design could do that on PostgreSQL).
    import threading

    from skillproof.registry import SQLiteSkillRegistry

    registry = SQLiteSkillRegistry(tmp_path / "registry.db")
    errors = []

    def write(n):
        try:
            for i in range(5):
                fingerprint = f"{n:02d}{i:02d}".ljust(64, "a")
                registry.register(f"tenant-{n % 2}", {"package_fingerprint": fingerprint, "metadata": {"name": f"s{n}"}},
                                  {"decision": "insufficient_evidence", "automatic_certification": False}, actor_id=f"u{n}")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=write, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    for tenant, expected in (("tenant-0", 20), ("tenant-1", 20)):
        assert sum(len(registry.list_versions(tenant, f"s{n}")) for n in range(8)) == expected
