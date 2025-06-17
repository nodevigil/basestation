-- Initialize the database with proper permissions and extensions
-- This script runs when the PostgreSQL container starts for the first time

-- Create extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- The database 'depin' and user 'simon' are already created by environment variables
-- This script can be used for additional initialization if needed

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE depin TO simon;

-- You can add any additional initialization here
-- For example, creating indexes, initial data, etc.
