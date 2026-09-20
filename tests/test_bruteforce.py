import pytest

from attacks.bruteforce import BruteForceAttack


def test_bruteforce_candidate_count_exact_math():
    attack = BruteForceAttack(
        hash_type="sha256",
        charset="d",
        min_length=1,
        max_length=3,
    )

    assert attack.candidate_count() == 10 + 100 + 1000


def test_bruteforce_rejects_zero_min_length():
    with pytest.raises(ValueError, match="min_length"):
        BruteForceAttack(hash_type="sha256", charset="d", min_length=0, max_length=3)


def test_bruteforce_chunks_do_not_exceed_thread_count():
    attack = BruteForceAttack(hash_type="sha256", charset="lud", max_processes=4)

    assert len(attack._charset_chunks()) == 4


def test_bruteforce_rejects_zero_processes():
    with pytest.raises(ValueError, match="max_processes"):
        BruteForceAttack(hash_type="sha256", charset="d", max_processes=0)
