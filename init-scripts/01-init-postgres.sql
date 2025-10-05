-- --------------------------------------------------------------------------
-- PostgreSQL initialization script
--
-- @author bnbong bbbong9@gmail.com
-- --------------------------------------------------------------------------

-- Create database if not exists (this is handled by POSTGRES_DB env var)
-- But we can set additional configurations here

-- Set timezone
SET timezone = 'UTC';

-- Create extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant permissions to admin user
GRANT ALL PRIVILEGES ON DATABASE phishing_data TO admin;

-- Create schema for application
CREATE SCHEMA IF NOT EXISTS public;
GRANT ALL ON SCHEMA public TO admin;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO admin;

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'PostgreSQL initialization completed for Wegis Server';
END
$$;
