"""
AI Engine Package — phát hiện bất thường trong log SOC.

Modules:
  extractor  — trích xuất features từ raw log
  model      — 3 models: Isolation Forest, EWMA, CUSUM
  scoring    — tính risk_score & phân loại
  explain    — giải thích rủi ro cho analyst
  engine     — detectors class-based (legacy, dùng bởi runner)
  runner     — background loop chạy mỗi 60s
"""
