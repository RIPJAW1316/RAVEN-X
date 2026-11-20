"""Render a bounded, server-assembled Cloud Run report from standard input."""
import json
import sys

from fleet_pdf import render_fleet_pdf


def main():
    data = sys.stdin.buffer.read(512 * 1024 + 1)
    if len(data) > 512 * 1024:
        raise ValueError("Report input exceeds the size limit")
    snapshot = json.loads(data)
    sys.stdout.buffer.write(render_fleet_pdf(snapshot["report"], review=snapshot["review"]))


if __name__ == "__main__":
    main()
