import json
import csv
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def write_output(data: dict, path: str, fmt: str = "json") -> None:
    if fmt == "json":
        _write_json(data, path)
    elif fmt == "csv":
        _write_csv(data, path)
    else:
        raise ValueError(f"Unknown format: {fmt}. Choose 'json' or 'csv'.")
    logger.info("Results saved to: %s", path)


def _write_json(data: dict, path: str) -> None:
    out = {k: v for k, v in data.items() if not k.startswith("_")}
    out.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


def _write_csv(data: dict, path: str) -> None:
    dtype = data.get("_type")
    if dtype == "scan":
        rows = format_scan_csv(data.get("open_ports", []))
        fieldnames = ["host", "port", "service", "banner"]
    elif dtype == "crack":
        rows = format_crack_csv(data.get("results", []))
        fieldnames = ["hash", "hash_type", "password", "cracked"]
    elif dtype == "analyze":
        rows = format_analyze_csv(data)
        fieldnames = ["password", "score", "strength"]
    else:
        raise ValueError(
            f"CSV output requires '_type' to be 'scan', 'crack', or 'analyze', got: {dtype!r}"
        )

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def format_scan_csv(ports: list) -> list:
    return [
        {
            "host": p.get("host", ""),
            "port": p["port"],
            "service": p.get("service") or "",
            "banner": p.get("banner") or "",
        }
        for p in ports
    ]


def format_crack_csv(results: list) -> list:
    return [
        {
            "hash": r["hash"],
            "hash_type": r.get("hash_type", ""),
            "password": r["password"] if r["password"] is not None else "",
            "cracked": r["cracked"],
        }
        for r in results
    ]


def format_analyze_csv(data: dict) -> list:
    results = data.get("results")
    if results is None and data.get("password") is not None:
        results = [data]
    return [
        {
            "password": r["password"],
            "score": r["score"],
            "strength": r["strength"],
        }
        for r in (results or [])
    ]
