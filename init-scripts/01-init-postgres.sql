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

-- Grant permissions to the runtime DB user
GRANT ALL PRIVILEGES ON DATABASE phishing_data TO CURRENT_USER;

-- Create schema for application
CREATE SCHEMA IF NOT EXISTS public;
GRANT ALL ON SCHEMA public TO CURRENT_USER;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO CURRENT_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO CURRENT_USER;

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'PostgreSQL initialization completed for Wegis Server';
END
$$;
