from attacks.bruteforce import BruteForceAttack


def test_bruteforce_candidate_count_exact_math():
    attack = BruteForceAttack(
        hash_type="sha256",
        charset="d",
        min_length=1,
        max_length=3,
    )

    assert attack.candidate_count() == 10 + 100 + 1000
