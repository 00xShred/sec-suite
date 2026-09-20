import json

from attacks.rainbow import RainbowAttack


def test_rainbow_candidate_count_counts_json_entries(tmp_path):
    table = tmp_path / "rainbow.json"
    table.write_text(json.dumps({"h1": "p1", "h2": "p2"}), encoding="utf-8")

    assert RainbowAttack(str(table)).candidate_count() == 2


def test_rainbow_loads_json_without_json_extension(tmp_path):
    table = tmp_path / "rainbow.db"
    table.write_text(json.dumps({"h1": "p1"}), encoding="utf-8")

    assert RainbowAttack(str(table)).crack("h1") == "p1"
