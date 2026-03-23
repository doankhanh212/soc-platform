"""
AI Detection Engine
Modules: Entropy, EWMA, CUSUM, Isolation Forest, Behavioral Baseline
Output: risk_score (0.0 → 1.0) + explanation per alert
"""
import math
import time
import numpy as np
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ─── Data Types ──────────────────────────────────────────────────

@dataclass
class AlertFeatures:
    src_ip: str
    timestamp: float          # unix epoch
    rule_level: int
    event_count_1m: int       # events from this IP in last 1 min
    event_count_5m: int
    failed_logins_5m: int
    unique_ports_5m: int
    bytes_out: int = 0
    entropy_score: float = 0.0


@dataclass
class RiskResult:
    risk_score: float         # 0.0 – 1.0
    triggered_models: list[str]
    details: dict
    should_block: bool = False


# ─── EWMA Detector ───────────────────────────────────────────────

class EWMADetector:
    """Exponentially Weighted Moving Average — detects traffic spikes."""

    def __init__(self, alpha: float = 0.2, threshold_sigma: float = 3.0):
        self.alpha = alpha
        self.threshold_sigma = threshold_sigma
        self._mean: dict[str, float] = defaultdict(float)
        self._var:  dict[str, float] = defaultdict(lambda: 1.0)

    def score(self, ip: str, value: float) -> tuple[float, dict]:
        mu  = self._mean[ip]
        var = self._var[ip]

        z = abs(value - mu) / max(math.sqrt(var), 1e-6)
        anomaly_score = min(z / self.threshold_sigma, 1.0)

        # Update EWMA
        self._mean[ip] = self.alpha * value + (1 - self.alpha) * mu
        diff = (value - self._mean[ip]) ** 2
        self._var[ip]  = self.alpha * diff + (1 - self.alpha) * var

        return anomaly_score, {"ewma_mean": round(mu, 2), "ewma_z": round(z, 2)}


# ─── CUSUM Detector ──────────────────────────────────────────────

class CUSUMDetector:
    """Cumulative Sum — detects sustained shifts, not just spikes."""

    def __init__(self, k: float = 0.5, h: float = 5.0):
        self.k = k
        self.h = h
        self._s_pos: dict[str, float] = defaultdict(float)
        self._s_neg: dict[str, float] = defaultdict(float)

    def score(self, ip: str, value: float, target: float = 0.0) -> tuple[float, dict]:
        s_pos = max(0, self._s_pos[ip] + value - target - self.k)
        s_neg = max(0, self._s_neg[ip] - value + target - self.k)
        self._s_pos[ip] = s_pos
        self._s_neg[ip] = s_neg

        cusum_val = max(s_pos, s_neg)
        score = min(cusum_val / self.h, 1.0)
        return score, {"cusum_s+": round(s_pos, 2), "cusum_s-": round(s_neg, 2)}


# ─── Entropy Detector ────────────────────────────────────────────

class EntropyDetector:
    """
    Shannon entropy on destination ports.
    Low entropy (same port repeatedly) = scan.
    Very high entropy (random ports) = possible exfil/ransomware.
    """

    def score(self, port_list: list[int]) -> tuple[float, dict]:
        if not port_list:
            return 0.0, {}

        counts: dict[int, int] = defaultdict(int)
        for p in port_list:
            counts[p] += 1

        total = len(port_list)
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
        max_entropy = math.log2(total) if total > 1 else 1.0

        normalized = entropy / max_entropy if max_entropy > 0 else 0.0

        # Score: very low OR very high entropy both suspicious
        score = 1.0 - abs(normalized - 0.5) * 2
        score = max(0.0, score)

        return round(score, 3), {
            "entropy": round(entropy, 3),
            "normalized": round(normalized, 3),
            "unique_ports": len(counts),
        }


# ─── Isolation Forest ────────────────────────────────────────────

class IsolationForestDetector:
    """
    sklearn IsolationForest retrained periodically on historical data.
    Features: [event_count_1m, event_count_5m, failed_logins_5m,
                unique_ports_5m, rule_level, entropy_score]
    """

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self._model = None
        self._trained = False
        self._buffer: list[list[float]] = []
        self._min_samples = 50

    def _feature_vector(self, feat: AlertFeatures) -> list[float]:
        return [
            feat.event_count_1m,
            feat.event_count_5m,
            feat.failed_logins_5m,
            feat.unique_ports_5m,
            feat.rule_level,
            feat.entropy_score,
        ]

    def add_sample(self, feat: AlertFeatures):
        self._buffer.append(self._feature_vector(feat))
        if len(self._buffer) > 5000:
            self._buffer.pop(0)
        if len(self._buffer) >= self._min_samples and len(self._buffer) % 50 == 0:
            self._retrain()

    def _retrain(self):
        from sklearn.ensemble import IsolationForest
        X = np.array(self._buffer)
        self._model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
        )
        self._model.fit(X)
        self._trained = True

    def score(self, feat: AlertFeatures) -> tuple[float, dict]:
        if not self._trained:
            return 0.0, {"isolation_forest": "not_trained_yet"}

        fv = np.array([self._feature_vector(feat)])
        raw_score = self._model.score_samples(fv)[0]   # negative: more anomalous
        # Map [-0.5, 0.5] → [1.0, 0.0]
        normalized = max(0.0, min(1.0, (-raw_score - 0.3) / 0.4))
        return round(normalized, 3), {"if_raw_score": round(raw_score, 4)}


# ─── Behavioral Baseline ─────────────────────────────────────────

class BehavioralBaseline:
    """
    Per-IP 24h sliding window baseline.
    Flags deviations from the IP's own historical pattern.
    """

    def __init__(self, window_hours: int = 24):
        self.window_seconds = window_hours * 3600
        # ip → deque of (timestamp, event_count)
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=1440))

    def record(self, ip: str, count: int):
        now = time.time()
        self._history[ip].append((now, count))

    def score(self, ip: str, current_count: int) -> tuple[float, dict]:
        history = self._history[ip]
        if len(history) < 5:
            return 0.0, {"baseline": "insufficient_data"}

        now = time.time()
        cutoff = now - self.window_seconds
        recent = [c for ts, c in history if ts >= cutoff]

        if not recent:
            return 0.0, {"baseline": "no_recent_data"}

        mean = np.mean(recent)
        std  = np.std(recent) or 1.0

        z = abs(current_count - mean) / std
        score = min(z / 4.0, 1.0)   # z=4 → score=1.0

        return round(score, 3), {
            "baseline_mean": round(float(mean), 1),
            "baseline_std":  round(float(std), 1),
            "baseline_z":    round(float(z), 2),
        }


# ─── Risk Scorer (Aggregator) ────────────────────────────────────

WEIGHTS = {
    "isolation_forest": 0.35,
    "ewma":             0.20,
    "cusum":            0.15,
    "entropy":          0.15,
    "behavioral":       0.15,
}


class RiskScorer:
    def __init__(self, block_threshold: float = 0.75):
        self.threshold  = block_threshold
        self.ewma       = EWMADetector()
        self.cusum      = CUSUMDetector()
        self.entropy    = EntropyDetector()
        self.iso_forest = IsolationForestDetector()
        self.behavioral = BehavioralBaseline()

    def evaluate(
        self,
        feat: AlertFeatures,
        recent_ports: Optional[list[int]] = None,
    ) -> RiskResult:
        scores: dict[str, float] = {}
        details: dict[str, dict]  = {}

        # Individual model scores
        s, d = self.ewma.score(feat.src_ip, feat.event_count_1m)
        scores["ewma"] = s;  details["ewma"] = d

        s, d = self.cusum.score(feat.src_ip, feat.event_count_5m)
        scores["cusum"] = s; details["cusum"] = d

        if recent_ports:
            s, d = self.entropy.score(recent_ports)
            scores["entropy"] = s; details["entropy"] = d
        else:
            scores["entropy"] = 0.0

        self.iso_forest.add_sample(feat)
        s, d = self.iso_forest.score(feat)
        scores["isolation_forest"] = s; details["isolation_forest"] = d

        self.behavioral.record(feat.src_ip, feat.event_count_5m)
        s, d = self.behavioral.score(feat.src_ip, feat.event_count_5m)
        scores["behavioral"] = s; details["behavioral"] = d

        # Weighted aggregate
        risk_score = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)
        risk_score = round(min(risk_score, 1.0), 4)

        triggered = [k for k, v in scores.items() if v >= 0.6]

        return RiskResult(
            risk_score=risk_score,
            triggered_models=triggered,
            details={
                "model_scores": {k: round(v, 3) for k, v in scores.items()},
                **details,
            },
            should_block=risk_score >= self.threshold,
        )


# Singleton instance reused across requests
_risk_scorer: Optional[RiskScorer] = None

def get_risk_scorer(threshold: float = 0.75) -> RiskScorer:
    global _risk_scorer
    if _risk_scorer is None:
        _risk_scorer = RiskScorer(block_threshold=threshold)
    return _risk_scorer
