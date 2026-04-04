"""Tests for rate limiting."""

from agent_guard import RateLimiter


class TestRateLimiter:
    def test_allows_within_burst(self):
        limiter = RateLimiter(rate=10, burst=5)
        for _ in range(5):
            assert limiter.allow()

    def test_blocks_after_burst(self):
        limiter = RateLimiter(rate=0.1, burst=2)
        assert limiter.allow()
        assert limiter.allow()
        assert not limiter.allow()

    def test_per_agent(self):
        limiter = RateLimiter(rate=0.1, burst=1, per_agent=True)
        assert limiter.allow("agent-1")
        assert limiter.allow("agent-2")  # different bucket
        assert not limiter.allow("agent-1")  # exhausted

    def test_remaining(self):
        limiter = RateLimiter(rate=10, burst=5)
        assert limiter.remaining() == 5
        limiter.allow()
        assert limiter.remaining() == 4

    def test_stats(self):
        limiter = RateLimiter(rate=10, burst=5, per_agent=True)
        stats = limiter.stats()
        assert stats["rate"] == 10
        assert stats["per_agent"]
