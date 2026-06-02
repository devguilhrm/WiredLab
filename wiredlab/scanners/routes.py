from __future__ import annotations

import subprocess
import threading
from collections.abc import Iterator


def inspect(stop_event: threading.Event | None = None) -> Iterator[str]:
    commands = [
        ("Interfaces", ["ip", "-br", "addr"]),
        ("IPv4 routes", ["ip", "route"]),
        ("IPv6 routes", ["ip", "-6", "route"]),
    ]

    for title, command in commands:
        if stop_event is not None and stop_event.is_set():
            break
        yield f"== {title} ==\n"
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except OSError as exc:
            yield f"[error] {' '.join(command)}: {exc}\n"
            continue

        output = result.stdout.strip() or result.stderr.strip() or "[empty]"
        for line in output.splitlines():
            yield line + "\n"
