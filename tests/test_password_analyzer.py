from utils.password_analyzer import analyze_password_strength, calculate_entropy


def test_returns_dict_with_required_keys():
    result = analyze_password_strength("P@ssw0rd!")
    assert isinstance(result, dict)
    assert "score" in result
    assert "strength" in result
    assert "feedback" in result
    assert "details" in result


def test_score_is_int_in_range():
    result = analyze_password_strength("abc")
    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100


def test_strength_label_very_weak():
    result = analyze_password_strength("a")
    assert result["strength"] == "VERY WEAK"


def test_strength_label_very_strong():
    result = analyze_password_strength("xK9!mP2@qZ#4nL5$")
    assert result["strength"] == "VERY STRONG"


def test_empty_password_returns_zero():
    result = analyze_password_strength("")
    assert result["score"] == 0


def test_details_has_expected_keys():
    result = analyze_password_strength("Hello123!")
    details = result["details"]
    for key in ("length", "has_upper", "has_lower", "has_digit", "has_special",
                "entropy_per_char", "pattern_penalty"):
        assert key in details, f"missing key: {key}"


def test_calculate_entropy_all_lower():
    # 6 * log2(26) ≈ 28.2
    e = calculate_entropy("abcdef")
    assert abs(e - 28.2) < 0.1


def test_repeated_password_has_low_entropy():
    result = analyze_password_strength("aaaaaaaaaaaaa")

    assert result["details"]["entropy_per_char"] < 10
    assert not any("High entropy" in item for item in result["feedback"])


def test_strong_password_can_reach_full_score():
    result = analyze_password_strength("xK9!mP2@qZ#4nL5$")

    assert result["score"] == 100
