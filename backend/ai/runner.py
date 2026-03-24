"""Background runner cho modular AI pipeline."""

import asyncio
import logging

from config import get_settings
from services.pipeline import analyze_batch

log = logging.getLogger("ai_engine")
cfg = get_settings()


async def run_once() -> int:
    """Chạy một vòng pipeline và trả về số kết quả đáng chú ý."""
    results = await analyze_batch()
    if results:
        log.info("AI Engine: analyzed %d suspicious IPs", len(results))
    else:
        log.debug("AI Engine: no suspicious activity in current window")
    return len(results)


async def ai_engine_loop() -> None:
    """Background loop gọi modular pipeline theo interval cấu hình."""
    interval = 60
    log.info(
        "AI Engine khởi động (interval=%ds, auto_block=%s)",
        interval,
        cfg.ai_block_auto,
    )
    await asyncio.sleep(5)

    while True:
        try:
            await run_once()
        except Exception as e:
            log.error("AI Engine lỗi: %s", e, exc_info=True)
        await asyncio.sleep(interval)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    asyncio.run(ai_engine_loop())
