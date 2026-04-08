"""
Anomaly Detection Models — 3 phương pháp phát hiện bất thường.

1. Isolation Forest  — phát hiện outlier đa chiều (unsupervised)
2. EWMA              — phát hiện spike traffic đột biến
3. CUSUM             — phát hiện behavior drift kéo dài

Kết hợp 3 model → anomaly_score tổng (0 → 1)
"""
import math
from collections import defaultdict
from threading import Lock

import numpy as np
from sklearn.ensemble import IsolationForest as _SKLearnIF


# ══════════════════════════════════════════════════════════════════
# 1. ISOLATION FOREST
# Features: connection_count, alert_frequency, request_rate, port_variance
# Output:   anomaly_score (0 → 1)
# ══════════════════════════════════════════════════════════════════

class IsolationForestModel:
    """Phát hiện outlier đa chiều — không cần nhãn (unsupervised)."""

    _KEYS = ("connection_count", "alert_frequency",
             "request_rate", "port_variance")

    def __init__(self, contamination: float = 0.1, min_samples: int = 10):
        self.contamination = contamination
        self._model: _SKLearnIF | None = None
        self._buffer: list[list[float]] = []
        self._min_samples = min_samples
        self._trained = False
        self._score_min = -1.0
        self._score_max = 0.0
        self._lock = Lock()

    # ── helpers ───────────────────────────────────────────────────

    def _vec(self, features: dict) -> list[float]:
        return [float(features.get(k, 0)) for k in self._KEYS]

    def _retrain(self):
        X = np.array(self._buffer)
        self._model = _SKLearnIF(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
        )
        self._model.fit(X)
        raw_scores = self._model.score_samples(X)
        self._score_min = float(raw_scores.min())
        self._score_max = float(raw_scores.max())
        self._trained = True

    # ── public API ────────────────────────────────────────────────

    def add_sample(self, features: dict):
        """Thêm sample, auto-retrain mỗi 25 samples."""
        with self._lock:
            self._buffer.append(self._vec(features))
            if len(self._buffer) > 5000:
                self._buffer.pop(0)
            if (len(self._buffer) >= self._min_samples
                    and len(self._buffer) % 25 == 0):
                self._retrain()

    def score(self, features: dict) -> float:
        """Trả về anomaly_score (0 → 1). Cao = bất thường hơn."""
        with self._lock:
            if self._trained and self._model is not None:
                fv = np.array([self._vec(features)])
                raw = float(self._model.score_samples(fv)[0])
                score_range = max(self._score_max - self._score_min, 1e-9)
                anomaly_score = (self._score_max - raw) / score_range
                score = round(max(0.0, min(1.0, anomaly_score)), 4)
            else:
                score = self._heuristic(features)

        # Score trước rồi mới học sample để tránh làm loãng outlier hiện tại.
        self.add_sample(features)
        return score

    def _heuristic(self, f: dict) -> float:
        """Fallback đơn giản khi chưa đủ data train."""
        s = 0.0
        if f.get("connection_count", 0) > 20:  s += 0.35
        if f.get("alert_frequency",  0) > 5:   s += 0.30
        if f.get("request_rate",     0) > 3:   s += 0.20
        if f.get("port_variance",    0) > 10:  s += 0.15
        return min(1.0, s)

    @property
    def trained(self) -> bool:
        return self._trained

    @property
    def sample_count(self) -> int:
        return len(self._buffer)


# ══════════════════════════════════════════════════════════════════
# 2. EWMA (Exponential Weighted Moving Average)
# Detect spike traffic — giá trị hiện tại vượt xa trung bình di động
# ══════════════════════════════════════════════════════════════════

class EWMAModel:
    """Phát hiện spike bất thường so với xu hướng."""

    def __init__(self, alpha: float = 0.3, threshold_sigma: float = 3.0):
        self.alpha           = alpha
        self.threshold_sigma = threshold_sigma
        self._mean: dict[str, float] = {}
        self._var:  dict[str, float] = {}

    def score(self, ip: str, value: float) -> float:
        """
        Tính anomaly score dựa trên EWMA z-score.
        Trả về 0 → 1.
        """
        if ip not in self._mean:
            self._mean[ip] = value
            self._var[ip] = max(abs(value), 1.0)
            return 0.0

        mu  = self._mean[ip]
        var = self._var[ip]

        z = abs(value - mu) / max(math.sqrt(var), 1e-6)
        anomaly_score = min(z / self.threshold_sigma, 1.0)

        # Cập nhật trung bình và phương sai
        self._mean[ip] = self.alpha * value + (1 - self.alpha) * mu
        diff = (value - self._mean[ip]) ** 2
        self._var[ip]  = self.alpha * diff + (1 - self.alpha) * var

        return round(anomaly_score, 4)


# ══════════════════════════════════════════════════════════════════
# 3. CUSUM (Cumulative Sum)
# Detect behavior drift — thay đổi kéo dài mà EWMA bỏ lỡ
# ══════════════════════════════════════════════════════════════════

class CUSUMModel:
    """Phát hiện drift hành vi kéo dài (slow attack)."""

    def __init__(self, k: float = 0.5, h: float = 5.0):
        self.k = k      # slack cho phép
        self.h = h      # ngưỡng quyết định
        self._s_pos: dict[str, float] = defaultdict(float)
        self._s_neg: dict[str, float] = defaultdict(float)
        self._target: dict[str, float] = {}

    def score(self, ip: str, value: float, target: float = 0.0) -> float:
        """
        Tính CUSUM score cho IP.
        Trả về 0 → 1. Cao = drift bất thường.
        """
        if ip not in self._target:
            self._target[ip] = value if value > 0 else target
            return 0.0

        target = self._target[ip]
        s_pos = max(0.0, self._s_pos[ip] + value - target - self.k)
        s_neg = max(0.0, self._s_neg[ip] - value + target - self.k)
        self._s_pos[ip] = s_pos
        self._s_neg[ip] = s_neg
        self._target[ip] = 0.2 * value + 0.8 * target

        cusum_val = max(s_pos, s_neg)
        return round(min(cusum_val / self.h, 1.0), 4)


# ══════════════════════════════════════════════════════════════════
# COMBINED — kết hợp 3 model → anomaly_score tổng
# ══════════════════════════════════════════════════════════════════

# Singleton model instances (giữ state giữa các lần gọi)
_if_model    = IsolationForestModel()
_ewma_model  = EWMAModel()
_cusum_model = CUSUMModel()


def compute_anomaly_score(features: dict) -> dict:
    """
    Chạy 3 models, trả về anomaly_score tổng hợp.

    Input:  features dict từ extractor
    Output: {
        "anomaly_score": float (0 → 1),
        "model_scores":  {"isolation_forest": …, "ewma": …, "cusum": …},
        "details":       {"if_trained": bool, "if_samples": int}
    }
    """
    ip = features.get("src_ip", "unknown")

    # 1. Isolation Forest (đa chiều)
    if_score = _if_model.score(features)

    # 2. EWMA trên request_rate (spike detection)
    ewma_score = _ewma_model.score(ip, features.get("request_rate", 0))

    # 3. CUSUM trên connection_count (drift detection)
    cusum_score = _cusum_model.score(
        ip, features.get("connection_count", 0), target=5.0
    )

    # Tổng hợp — IF nặng nhất vì đa chiều
    anomaly_score = (
        0.50 * if_score
      + 0.30 * ewma_score
      + 0.20 * cusum_score
    )
    anomaly_score = round(min(1.0, anomaly_score), 4)

    return {
        "anomaly_score": anomaly_score,
        "model_scores": {
            "isolation_forest": if_score,
            "ewma":             ewma_score,
            "cusum":            cusum_score,
        },
        "details": {
            "if_trained":  _if_model.trained,
            "if_samples":  _if_model.sample_count,
        },
    }
