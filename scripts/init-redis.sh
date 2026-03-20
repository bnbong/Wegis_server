#!/bin/sh
# --------------------------------------------------------------------------
# Redis initialization script
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------

echo "Initializing Redis with default domain lists..."

REDIS_HOST="${REDIS_HOST:-redis}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_DB="${REDIS_DB:-0}"

# Wait for Redis to be ready
while ! redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" ping; do
  echo "Waiting for Redis..."
  sleep 1
done

echo "Redis is ready! Adding default domain lists..."

# Add default whitelist domains
echo "Adding whitelist domains..."
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" SADD "wegis:whitelist:domains" \
  "google.com" \
  "amazon.com" \
  "microsoft.com" \
  "apple.com" \
  "facebook.com" \
  "instagram.com" \
  "twitter.com" \
  "linkedin.com" \
  "github.com" \
  "stackoverflow.com" \
  "wikipedia.org" \
  "youtube.com" \
  "netflix.com" \
  "cnn.com" \
  "bbc.com" \
  "nytimes.com" \
  "reddit.com" \
  "openai.com" \
  "naver.com" \
  "daum.net" \
  "kakao.com" \
  "samsung.com" \
  "lg.com"

# Add default whitelist patterns
echo "Adding whitelist patterns..."
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" SADD "wegis:whitelist:patterns" \
  "*.google.com" \
  "*.amazon.com" \
  "*.microsoft.com" \
  "*.apple.com" \
  "*.github.com" \
  "*.stackoverflow.com" \
  "*.wikipedia.org" \
  "*.youtube.com" \
  "*.naver.com" \
  "*.kakao.com"

# Initialize empty blacklist keys
# Using placeholder method to create empty sets
echo "Initializing empty blacklist keys..."
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" SADD "wegis:blacklist:domains" "__placeholder__"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" SREM "wegis:blacklist:domains" "__placeholder__"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" SADD "wegis:blacklist:patterns" "__placeholder__"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" SREM "wegis:blacklist:patterns" "__placeholder__"

echo "Redis initialization completed!"
echo "Whitelist domains count: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" SCARD wegis:whitelist:domains)"
echo "Whitelist patterns count: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" SCARD wegis:whitelist:patterns)"
echo "Blacklist keys initialized (empty)"
