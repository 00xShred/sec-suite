import json
import csv
import os
import tempfile
from utils.output import write_output, format_scan_csv, format_crack_csv


def test_write_json_creates_file():
    data = {"hash": "abc", "password": "secret", "cracked": True}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        write_output(data, path, "json")
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["password"] == "secret"
    finally:
        os.unlink(path)


def test_write_csv_crack_creates_file():
    data = {
        "_type": "crack",
        "results": [
            {"hash": "abc", "hash_type": "md5", "password": "hi", "cracked": True},
            {"hash": "xyz", "hash_type": "md5", "password": None, "cracked": False},
        ],
    }
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
        path = f.name
    try:
        write_output(data, path, "csv")
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["password"] == "hi"
        assert rows[1]["cracked"] == "False"
    finally:
        os.unlink(path)


def test_write_csv_scan_creates_file():
    data = {
        "_type": "scan",
        "open_ports": [
            {"host": "127.0.0.1", "port": 22, "banner": "SSH-2.0"},
            {"host": "127.0.0.1", "port": 80, "banner": ""},
        ],
    }
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
        path = f.name
    try:
        write_output(data, path, "csv")
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        assert int(rows[0]["port"]) == 22
        assert rows[0]["host"] == "127.0.0.1"
    finally:
        os.unlink(path)


def test_format_scan_csv_returns_rows():
    ports = [{"host": "10.0.0.1", "port": 443, "banner": "TLS"}, {"host": "10.0.0.1", "port": 8080, "banner": ""}]
    rows = format_scan_csv(ports)
    assert rows[0] == {"host": "10.0.0.1", "port": 443, "banner": "TLS"}


def test_format_crack_csv_none_password():
    results = [{"hash": "x", "hash_type": "md5", "password": None, "cracked": False}]
    rows = format_crack_csv(results)
    assert rows[0]["password"] == ""


def test_json_output_includes_timestamp():
    data = {"foo": "bar"}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        write_output(data, path, "json")
        with open(path) as f:
            loaded = json.load(f)
        assert "timestamp" in loaded
    finally:
        os.unlink(path)


def test_json_output_strips_underscore_keys():
    data = {"_type": "crack", "result": "found"}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        write_output(data, path, "json")
        with open(path) as f:
            loaded = json.load(f)
        assert "_type" not in loaded
        assert "result" in loaded
    finally:
        os.unlink(path)


def test_write_output_unknown_format_raises():
    import pytest
    data = {"foo": "bar"}
    with pytest.raises(ValueError, match="json"):
        write_output(data, "/tmp/irrelevant.xyz", "xml")


def test_write_csv_unknown_type_raises():
    import pytest
    data = {"_type": "unknown", "results": []}
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
        path = f.name
    try:
        with pytest.raises(ValueError, match="scan"):
            write_output(data, path, "csv")
    finally:
        if os.path.exists(path):
            os.unlink(path)
