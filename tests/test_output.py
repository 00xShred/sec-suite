import csv
import json
import os
import tempfile

import pytest

from utils.output import write_output, format_scan_csv, format_crack_csv, format_analyze_csv


def temp_path(suffix):
    d = tempfile.TemporaryDirectory()
    return d, os.path.join(d.name, f"out{suffix}")


def test_write_json_creates_file():
    data = {"hash": "abc", "password": "secret", "cracked": True}
    tmp, path = temp_path(".json")
    with tmp:
        write_output(data, path, "json")
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["password"] == "secret"


def test_write_csv_crack_creates_file():
    data = {
        "_type": "crack",
        "results": [
            {"hash": "abc", "hash_type": "md5", "password": "hi", "cracked": True},
            {"hash": "xyz", "hash_type": "md5", "password": None, "cracked": False},
        ],
    }
    tmp, path = temp_path(".csv")
    with tmp:
        write_output(data, path, "csv")
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["password"] == "hi"
        assert rows[1]["cracked"] == "False"


def test_write_csv_scan_creates_file():
    data = {
        "_type": "scan",
        "open_ports": [
            {"host": "127.0.0.1", "port": 22, "service": "SSH", "banner": "SSH-2.0"},
            {"host": "127.0.0.1", "port": 80, "service": "HTTP", "banner": ""},
        ],
    }
    tmp, path = temp_path(".csv")
    with tmp:
        write_output(data, path, "csv")
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        assert int(rows[0]["port"]) == 22
        assert rows[0]["host"] == "127.0.0.1"
        assert rows[0]["service"] == "SSH"


def test_format_scan_csv_returns_rows():
    ports = [
        {"host": "10.0.0.1", "port": 443, "service": "HTTPS", "banner": "TLS"},
        {"host": "10.0.0.1", "port": 8080, "service": "HTTP-Alt", "banner": ""},
    ]
    rows = format_scan_csv(ports)
    assert rows[0] == {"host": "10.0.0.1", "port": 443, "service": "HTTPS", "banner": "TLS"}


def test_format_crack_csv_none_password():
    results = [{"hash": "x", "hash_type": "md5", "password": None, "cracked": False}]
    rows = format_crack_csv(results)
    assert rows[0]["password"] == ""


def test_write_csv_analyze_creates_file():
    data = {
        "_type": "analyze",
        "results": [
            {"password": "secret", "score": 40, "strength": "Weak"},
            {"password": "correct horse battery staple", "score": 95, "strength": "Very Strong"},
        ],
    }
    tmp, path = temp_path(".csv")
    with tmp:
        write_output(data, path, "csv")
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0] == {"password": "secret", "score": "40", "strength": "Weak"}
        assert rows[1]["strength"] == "Very Strong"


def test_format_analyze_csv_single_password_shape():
    rows = format_analyze_csv({"password": "secret", "score": 40, "strength": "Weak"})
    assert rows == [{"password": "secret", "score": 40, "strength": "Weak"}]


def test_json_output_includes_timestamp():
    tmp, path = temp_path(".json")
    with tmp:
        write_output({"foo": "bar"}, path, "json")
        with open(path) as f:
            loaded = json.load(f)
        assert "timestamp" in loaded


def test_json_output_strips_underscore_keys():
    tmp, path = temp_path(".json")
    with tmp:
        write_output({"_type": "crack", "result": "found"}, path, "json")
        with open(path) as f:
            loaded = json.load(f)
        assert "_type" not in loaded
        assert "result" in loaded


def test_write_output_unknown_format_raises():
    with pytest.raises(ValueError, match="json"):
        write_output({"foo": "bar"}, "/tmp/irrelevant.xyz", "xml")


def test_write_csv_unknown_type_raises():
    tmp, path = temp_path(".csv")
    with tmp, pytest.raises(ValueError, match="scan"):
        write_output({"_type": "unknown", "results": []}, path, "csv")


def test_write_output_refuses_existing_file():
    tmp, path = temp_path(".json")
    with tmp:
        with open(path, "w", encoding="utf-8") as f:
            f.write("keep")
        with pytest.raises(FileExistsError):
            write_output({"foo": "bar"}, path, "json")
        with open(path, encoding="utf-8") as f:
            assert f.read() == "keep"
