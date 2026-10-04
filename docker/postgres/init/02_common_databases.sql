-- Idempotent databases on the shared Postgres.
-- Runs on every common-stack start (not only the first volume init).
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', 'android_forensic', 'android_forensic')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'android_forensic')\gexec

SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', 'ios_forensic', 'ios_forensic')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ios_forensic')\gexec

SELECT 'CREATE DATABASE android_forensic OWNER android_forensic'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'android_forensic')\gexec

SELECT 'CREATE DATABASE ios_forensic OWNER ios_forensic'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'ios_forensic')\gexec

SELECT 'CREATE DATABASE vuln OWNER forensic'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'vuln')\gexec

SELECT 'CREATE DATABASE mobile_extract OWNER forensic'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'mobile_extract')\gexec

\c android_forensic
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

\c ios_forensic
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

\c vuln
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

\c mobile_extract
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

\c forensic
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;
