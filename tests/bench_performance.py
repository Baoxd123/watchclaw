"""Performance benchmark: Layer 1+2 processing speed."""

import time

from watchclaw.engine import WatchClawEngine
from watchclaw.parser import SimulatedEventGenerator


def run_benchmark(n: int = 1000) -> None:
    engine = WatchClawEngine()
    gen = SimulatedEventGenerator()
    events = [gen.generate_normal() for _ in range(n)]

    # Disable file I/O to measure pure processing speed
    engine._action_log_path = type(engine._action_log_path)("/dev/null")

    start = time.perf_counter()
    for e in events:
        engine.process_event(e)
    elapsed = time.perf_counter() - start

    rate = n / elapsed
    per_event_ms = elapsed / n * 1000

    print(f"{n} events in {elapsed:.3f}s = {rate:.0f} events/sec")
    print(f"Per event: {per_event_ms:.2f}ms")
    print(f"Target: < 5ms per event → {'PASS' if per_event_ms < 5 else 'FAIL'}")


if __name__ == "__main__":
    run_benchmark()
