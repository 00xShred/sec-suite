from types import SimpleNamespace

import main
from main import password_cracker_mode


def test_rainbow_attack_requires_table(capsys):
    args = SimpleNamespace(
        attack_mode="rainbow",
        rainbow_table=None,
        test_password=None,
        count=False,
        target_file=None,
        target_hash="abc",
    )

    assert password_cracker_mode(args) is None
    assert "--rainbow-table is required" in capsys.readouterr().out


def test_crack_requires_target_or_count(capsys):
    args = SimpleNamespace(
        attack_mode="dictionary",
        rainbow_table=None,
        test_password=None,
        count=False,
        target_file=None,
        target_hash=None,
    )

    assert password_cracker_mode(args) is None
    assert "Provide --target-hash" in capsys.readouterr().out


def test_multi_hash_reuses_attack_for_same_hash_type(monkeypatch, tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("aaa\nbbb\n", encoding="utf-8")
    build_count = 0

    class FakeAttack:
        def crack(self, target_hash):
            return None

    def fake_build_attack(args):
        nonlocal build_count
        build_count += 1
        return FakeAttack()

    monkeypatch.setattr(main, "_build_attack", fake_build_attack)
    args = SimpleNamespace(
        attack_mode="dictionary",
        hash_type="md5",
        rainbow_table=None,
        test_password=None,
        count=False,
        target_file=str(hash_file),
        target_hash=None,
    )

    password_cracker_mode(args)

    assert build_count == 1


def test_crack_rejects_zero_threads(capsys):
    args = SimpleNamespace(
        attack_mode="dictionary",
        hash_type="md5",
        rainbow_table=None,
        test_password=None,
        count=False,
        target_file=None,
        target_hash="abc",
        threads=0,
    )

    assert password_cracker_mode(args) is None
    assert "--threads must be at least 1" in capsys.readouterr().out
