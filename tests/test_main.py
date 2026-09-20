from types import SimpleNamespace

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
