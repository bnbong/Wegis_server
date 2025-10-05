#!/bin/sh
# --------------------------------------------------------------------------
# Redis initialization script
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------

echo "Initializing Redis with default domain lists..."

# Wait for Redis to be ready
while ! redis-cli -h redis -p 6379 ping; do
  echo "Waiting for Redis..."
  sleep 1
done

echo "Redis is ready! Adding default domain lists..."

# Add default whitelist domains
echo "Adding whitelist domains..."
redis-cli -h redis -p 6379 SADD "wegis:whitelist:domains" \
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
redis-cli -h redis -p 6379 SADD "wegis:whitelist:patterns" \
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
redis-cli -h redis -p 6379 SADD "wegis:blacklist:domains" "__placeholder__"
redis-cli -h redis -p 6379 SREM "wegis:blacklist:domains" "__placeholder__"
redis-cli -h redis -p 6379 SADD "wegis:blacklist:patterns" "__placeholder__"
redis-cli -h redis -p 6379 SREM "wegis:blacklist:patterns" "__placeholder__"

echo "Redis initialization completed!"
echo "Whitelist domains count: $(redis-cli -h redis -p 6379 SCARD wegis:whitelist:domains)"
echo "Whitelist patterns count: $(redis-cli -h redis -p 6379 SCARD wegis:whitelist:patterns)"
echo "Blacklist keys initialized (empty)"
