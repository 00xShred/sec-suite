import json
import csv
import logging
import os
import tempfile
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def write_output(data: dict, path: str, fmt: str = "json", overwrite: bool = False) -> None:
    if fmt == "json":
        _write_json(data, path, overwrite)
    elif fmt == "csv":
        _write_csv(data, path, overwrite)
    else:
        raise ValueError(f"Unknown format: {fmt}. Choose 'json' or 'csv'.")
    logger.info("Results saved to: %s", path)


def _replace_existing(path: str, overwrite: bool) -> None:
    if os.path.exists(path) and not overwrite:
        raise FileExistsError(f"Output file already exists: {path}")


def _write_json(data: dict, path: str, overwrite: bool = False) -> None:
    _replace_existing(path, overwrite)
    out = {k: v for k, v in data.items() if not k.startswith("_")}
    out.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".sec-suite-", suffix=".tmp", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _write_csv(data: dict, path: str, overwrite: bool = False) -> None:
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

    rows = [{k: _safe_csv_cell(v) for k, v in row.items()} for row in rows]

    _replace_existing(path, overwrite)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".sec-suite-", suffix=".tmp", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _safe_csv_cell(value):
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@"):
        return "'" + value
    return value


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
