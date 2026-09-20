import tools.network_scanner as network_scanner
from tools.network_scanner import NetworkScanner


def test_non_root_syn_scan_falls_back_to_connect(monkeypatch):
    calls = []
    scanner = NetworkScanner("127.0.0.1", ports="1", scan_type="syn")
    scanner._get_hosts = lambda: ["127.0.0.1"]
    scanner._connect_scan_port = lambda host, port: calls.append((host, port)) or (False, None)
    monkeypatch.setattr(network_scanner, "_SCAPY_AVAILABLE", True)
    monkeypatch.setattr(network_scanner.os, "name", "posix", raising=False)
    monkeypatch.setattr(network_scanner.os, "geteuid", lambda: 1000)

    scanner.scan()

    assert calls == [("127.0.0.1", 1)]


def test_get_hosts_rejects_huge_cidr():
    scanner = NetworkScanner("10.0.0.0/8", ports="1")

    try:
        scanner._get_hosts()
    except ValueError as exc:
        assert "too large" in str(exc)
    else:
        raise AssertionError("large CIDR was accepted")
