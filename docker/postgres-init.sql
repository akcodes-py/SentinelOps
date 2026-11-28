-- Least-privilege read-only role for agent SELECT queries (PDR 6.3.5).
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'sentinel_ro') THEN
        CREATE ROLE sentinel_ro LOGIN PASSWORD 'sentinel_ro_change_me';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE sentinel TO sentinel_ro;
GRANT USAGE ON SCHEMA public TO sentinel_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO sentinel_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO sentinel_ro;
