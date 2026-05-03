from attacks.rules import apply_rules, RULE_SETS, BUILTIN_RULES


def test_apply_noop_yields_word():
    results = list(apply_rules("hello", ["noop"]))
    assert "hello" in results


def test_apply_capitalize():
    results = list(apply_rules("hello", ["capitalize"]))
    assert "Hello" in results


def test_apply_leet():
    results = list(apply_rules("password", ["leet"]))
    assert "p4ssw0rd" in results


def test_apply_append_digits_yields_ten_variants():
    results = list(apply_rules("cat", ["append_digits"]))
    for d in range(10):
        assert f"cat{d}" in results


def test_apply_append_year_includes_2024():
    results = list(apply_rules("cat", ["append_year"]))
    assert "cat2024" in results


def test_apply_reverse():
    results = list(apply_rules("abc", ["reverse"]))
    assert "cba" in results


def test_no_duplicates_in_output():
    results = list(apply_rules("hello", ["noop", "lower"]))
    assert len(results) == len(set(results))


def test_rule_set_all_contains_words():
    results = list(apply_rules("hello", RULE_SETS["all"]))
    assert len(results) > 5


def test_rule_set_basic_subset():
    for name in RULE_SETS["basic"]:
        assert name in RULE_SETS["all"]


def test_apply_upper():
    results = list(apply_rules("hello", ["upper"]))
    assert "HELLO" in results


def test_apply_double():
    results = list(apply_rules("cat", ["double"]))
    assert "catcat" in results


def test_apply_toggle_case():
    results = list(apply_rules("Hello", ["toggle_case"]))
    assert "hELLO" in results


def test_apply_append_special():
    results = list(apply_rules("cat", ["append_special"]))
    assert "cat!" in results
    assert "cat123" in results


def test_apply_prepend_digits():
    results = list(apply_rules("cat", ["prepend_digits"]))
    for d in range(10):
        assert f"{d}cat" in results


def test_unknown_rule_is_skipped():
    results = list(apply_rules("hello", ["nonexistent_rule"]))
    assert results == []


def test_numbers_rule_set_produces_year_variants():
    import datetime
    results = list(apply_rules("cat", RULE_SETS["numbers"]))
    current_year = str(datetime.date.today().year)
    assert f"cat{current_year}" in results


def test_composition_capitalize_plus_special():
    # Two-level composition: capitalize "cat" -> "Cat", then append_special -> "Cat!"
    results = list(apply_rules("cat", ["capitalize", "append_special"]))
    assert "Cat!" in results
