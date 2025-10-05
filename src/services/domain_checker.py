# --------------------------------------------------------------------------
# Domain checker service module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import fnmatch
import idna
import logging
import tldextract
from typing import Optional
from urllib.parse import urlparse

import redis.asyncio as aioredis

from src.core.config import settings

logger = logging.getLogger("main")


def _extract_domain(url: str) -> Optional[str]:
    """Extract registrable domain from URL"""
    try:
        parsed = urlparse(
            url if url.startswith(("http://", "https://")) else f"http://{url}"
        )
        host = parsed.hostname
        if not host:
            return None

        host = host.strip().lower().rstrip(".")
        try:
            host = idna.encode(host).decode("ascii")
        except idna.IDNAError:
            return None

        ex = tldextract.extract(host)
        if not ex.domain or not ex.suffix:
            return None

        return f"{ex.domain}.{ex.suffix}".lower()
    except Exception as e:
        logger.warning(f"Failed to extract domain from URL {url}: {e}")
        return None


class DomainChecker:
    """Redis-based domain whitelist/blacklist check service"""

    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client
        self.whitelist_key = f"{settings.REDIS_NAMESPACE}:whitelist:domains"
        self.blacklist_key = f"{settings.REDIS_NAMESPACE}:blacklist:domains"
        self.whitelist_pattern_key = f"{settings.REDIS_NAMESPACE}:whitelist:patterns"
        self.blacklist_pattern_key = f"{settings.REDIS_NAMESPACE}:blacklist:patterns"

    async def is_whitelisted(self, url: str) -> bool:
        """Check if URL is in whitelist"""
        domain = _extract_domain(url)
        if not domain:
            return False

        # Check exact domain matching
        is_member = await self.redis.sismember(self.whitelist_key, domain)  # type: ignore
        if is_member:
            logger.info(f"Domain {domain} found in whitelist")
            return True

        # Check pattern matching
        if settings.DOMAIN_ENABLE_PATTERNS:
            patterns = await self.redis.smembers(self.whitelist_pattern_key)  # type: ignore
            for pattern in patterns:
                if self._match_pattern(domain, pattern):
                    logger.info(f"Domain {domain} matches whitelist pattern {pattern}")
                    return True

        return False

    async def is_blacklisted(self, url: str) -> bool:
        """Check if URL is in blacklist"""
        domain = _extract_domain(url)
        if not domain:
            return False

        # Check exact domain matching
        is_member = await self.redis.sismember(self.blacklist_key, domain)  # type: ignore
        if is_member:
            logger.info(f"Domain {domain} found in blacklist")
            return True

        # Check pattern matching
        if settings.DOMAIN_ENABLE_PATTERNS:
            patterns = await self.redis.smembers(self.blacklist_pattern_key)  # type: ignore
            for pattern in patterns:
                if self._match_pattern(domain, pattern):
                    logger.info(f"Domain {domain} matches blacklist pattern {pattern}")
                    return True

        return False

    @staticmethod
    def _match_pattern(domain: str, pattern: str) -> bool:
        """Domain pattern matching"""
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return domain == suffix or domain.endswith("." + suffix)
        return fnmatch.fnmatch(domain, pattern)

    async def get_domain_status(self, url: str) -> str:
        """Return domain status (whitelist, blacklist, unknown)"""
        if await self.is_whitelisted(url):
            return "whitelist"
        elif await self.is_blacklisted(url):
            return "blacklist"
        else:
            return "unknown"
