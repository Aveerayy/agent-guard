"""Trust scoring — track and evaluate agent trustworthiness over time."""

from __future__ import annotations

import threading
import time
from typing import Any

from pydantic import BaseModel, Field


class TrustScore(BaseModel):
    """Current trust state for an agent, scored 0-1000."""

    agent_id: str
    score: int = Field(default=500, ge=0, le=1000)
    level: str = "medium"
    successful_actions: int = 0
    failed_actions: int = 0
    policy_violations: int = 0
    last_updated: float = Field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        total = self.successful_actions + self.failed_actions
        return self.successful_actions / total if total > 0 else 0.0

    def _update_level(self) -> None:
        if self.score >= 800:
            self.level = "high"
        elif self.score >= 500:
            self.level = "medium"
        elif self.score >= 200:
            self.level = "low"
        else:
            self.level = "untrusted"

    def __repr__(self) -> str:
        return f"TrustScore({self.agent_id}: {self.score}/1000 [{self.level}])"


class TrustEngine:
    """Manages trust scores for all agents in the system.

    Usage:
        trust = TrustEngine()
        trust.record_success("agent-1")
        trust.record_success("agent-1")
        trust.record_violation("agent-1")

        score = trust.get_score("agent-1")
        print(score)  # TrustScore(agent-1: 510/1000 [medium])

        if trust.is_trusted("agent-1", min_score=400):
            # proceed
            ...
    """

    def __init__(
        self,
        *,
        initial_score: int = 500,
        success_reward: int = 10,
        failure_penalty: int = 20,
        violation_penalty: int = 50,
        decay_rate: float = 0.001,
    ):
        self._scores: dict[str, TrustScore] = {}
        self._initial_score = initial_score
        self._success_reward = success_reward
        self._failure_penalty = failure_penalty
        self._violation_penalty = violation_penalty
        self._decay_rate = decay_rate
        self._lock = threading.Lock()

    def get_score(self, agent_id: str) -> TrustScore:
        with self._lock:
            if agent_id not in self._scores:
                ts = TrustScore(agent_id=agent_id, score=self._initial_score)
                ts._update_level()
                self._scores[agent_id] = ts
            return self._scores[agent_id]

    def record_success(self, agent_id: str) -> TrustScore:
        score = self.get_score(agent_id)
        with self._lock:
            score.successful_actions += 1
            score.score = min(1000, score.score + self._success_reward)
            score.last_updated = time.time()
            score._update_level()
        return score

    def record_failure(self, agent_id: str) -> TrustScore:
        score = self.get_score(agent_id)
        with self._lock:
            score.failed_actions += 1
            score.score = max(0, score.score - self._failure_penalty)
            score.last_updated = time.time()
            score._update_level()
        return score

    def record_violation(self, agent_id: str) -> TrustScore:
        """Record a policy violation — larger penalty than a simple failure."""
        score = self.get_score(agent_id)
        with self._lock:
            score.policy_violations += 1
            score.score = max(0, score.score - self._violation_penalty)
            score.last_updated = time.time()
            score._update_level()
        return score

    def is_trusted(self, agent_id: str, min_score: int = 300) -> bool:
        return self.get_score(agent_id).score >= min_score

    def set_score(self, agent_id: str, score: int) -> TrustScore:
        ts = self.get_score(agent_id)
        with self._lock:
            ts.score = max(0, min(1000, score))
            ts.last_updated = time.time()
            ts._update_level()
        return ts

    def all_scores(self) -> dict[str, TrustScore]:
        return dict(self._scores)

    def summary(self) -> dict[str, Any]:
        scores = list(self._scores.values())
        if not scores:
            return {"agents": 0}
        return {
            "agents": len(scores),
            "avg_score": sum(s.score for s in scores) / len(scores),
            "min_score": min(s.score for s in scores),
            "max_score": max(s.score for s in scores),
            "untrusted_agents": [s.agent_id for s in scores if s.level == "untrusted"],
        }
