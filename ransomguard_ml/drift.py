"""Baseline drift monitor for the v2 detector.

Tracks the running mean of recent malicious-probability scores and warns when it
drifts far above the benign baseline learned at training time — an early sign
that the environment changed and the model may need retraining.
"""
from __future__ import annotations

from collections import deque


class DriftMonitor:
    def __init__(self, benign_mean: float, benign_std: float, warn_z: float = 3.0, window: int = 20):
        self.benign_mean = benign_mean
        self.benign_std = max(benign_std, 1e-6)
        self.warn_z = warn_z
        self._recent: deque[float] = deque(maxlen=window)
        self._warned = False

    def update(self, prob: float) -> bool:
        self._recent.append(prob)
        if len(self._recent) < self._recent.maxlen:
            return False
        mean = sum(self._recent) / len(self._recent)
        z = (mean - self.benign_mean) / self.benign_std
        if z >= self.warn_z and not self._warned:
            self._warned = True
            return True
        if z < self.warn_z * 0.5:
            self._warned = False
        return False

    def stats(self) -> dict:
        mean = sum(self._recent) / max(1, len(self._recent))
        z = (mean - self.benign_mean) / self.benign_std
        return {"recent_mean": mean, "z": z}
