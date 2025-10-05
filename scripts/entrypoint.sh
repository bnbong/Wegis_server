#!/bin/sh
# --------------------------------------------------------------------------
# Entrypoint script for Wegis Server
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------

set -e

echo "Starting Wegis Server initialization..."

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
while ! nc -z ${POSTGRES_HOST:-postgres} ${POSTGRES_PORT:-5432}; do
  sleep 0.1
done
echo "PostgreSQL is ready!"

# Wait for Redis to be ready
echo "Waiting for Redis..."
while ! nc -z ${REDIS_HOST:-redis} ${REDIS_PORT:-6379}; do
  sleep 0.1
done
echo "Redis is ready!"

# Wait for MongoDB to be ready
echo "Waiting for MongoDB..."
while ! nc -z ${MONGODB_HOST:-mongodb} ${MONGODB_PORT:-27017}; do
  sleep 0.1
done
echo "MongoDB is ready!"

# Run database migrations
echo "Running database migrations..."
alembic upgrade head

echo "Initialization complete! Starting application..."

# Execute the original command
exec "$@"
