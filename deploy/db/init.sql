-- The role SkillProof connects as: owns its tables (it creates them on start) but is not a superuser and cannot bypass
-- row-level security, so every tenant table's FORCE ROW LEVEL SECURITY applies to it. Change the password.
CREATE ROLE skillproof_app LOGIN PASSWORD 'change-me-app' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT CONNECT, CREATE ON DATABASE skillproof TO skillproof_app;
GRANT USAGE, CREATE ON SCHEMA public TO skillproof_app;
