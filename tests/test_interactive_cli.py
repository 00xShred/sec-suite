from interactive_cli import InteractiveCLI


def test_validate_hash_type_rejects_unknown(monkeypatch):
    cli = InteractiveCLI()
    monkeypatch.setattr(cli, "wait_for_enter", lambda: None)

    assert not cli.validate_hash_type("sha-256")


def test_validate_hash_type_accepts_known():
    assert InteractiveCLI().validate_hash_type("sha256")
