import re
import math
import string
from typing import Dict, Tuple


def analyze_password_strength(password: str) -> int:
    """
    Analyze password strength and return a score from 0-100
    """
    if not password:
        return 0

    score = 0
    feedback = []

    # Length check (max 25 points)
    length = len(password)
    if length >= 12:
        score += 25
        feedback.append("✓ Good length (12+ characters)")
    elif length >= 8:
        score += 15
        feedback.append("✓ Acceptable length (8-11 characters)")
    else:
        score += 5
        feedback.append("✗ Too short (less than 8 characters)")

    # Character variety checks
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    # Character variety (max 40 points)
    char_variety = sum([has_upper, has_lower, has_digit, has_special])
    if char_variety == 4:
        score += 40
        feedback.append("✓ Excellent character variety (upper, lower, digits, special)")
    elif char_variety == 3:
        score += 25
        feedback.append("✓ Good character variety (3 character types)")
    elif char_variety == 2:
        score += 15
        feedback.append("✓ Basic character variety (2 character types)")
    else:
        score += 5
        feedback.append("✗ Poor character variety (only 1 character type)")

    # Entropy calculation (max 20 points)
    entropy = calculate_entropy(password)
    if entropy > 4.0:
        score += 20
        feedback.append(f"✓ High entropy ({entropy:.2f} bits per character)")
    elif entropy > 3.0:
        score += 15
        feedback.append(f"✓ Moderate entropy ({entropy:.2f} bits per character)")
    else:
        score += 5
        feedback.append(f"✗ Low entropy ({entropy:.2f} bits per character)")

    # Common pattern penalties (max -15 points penalty)
    penalty = check_common_patterns(password)
    score -= penalty

    if penalty > 0:
        feedback.append(f"✗ Contains common patterns (-{penalty} points)")

    # Ensure score is within bounds
    final_score = max(0, min(100, score))

    # Print feedback
    print(f"\nPassword Analysis for: {password}")
    print("=" * 50)
    for item in feedback:
        print(item)
    print(f"\nFinal Strength Score: {final_score}/100")

    if final_score >= 80:
        print("Strength: VERY STRONG")
    elif final_score >= 60:
        print("Strength: STRONG")
    elif final_score >= 40:
        print("Strength: MODERATE")
    elif final_score >= 20:
        print("Strength: WEAK")
    else:
        print("Strength: VERY WEAK")

    return final_score


def calculate_entropy(password: str) -> float:
    """Calculate password entropy in bits per character"""
    char_set_size = 0

    if any(c.islower() for c in password):
        char_set_size += 26
    if any(c.isupper() for c in password):
        char_set_size += 26
    if any(c.isdigit() for c in password):
        char_set_size += 10
    if any(c in string.punctuation for c in password):
        char_set_size += 32

    if char_set_size == 0:
        return 0

    return math.log2(char_set_size)


def check_common_patterns(password: str) -> int:
    """Check for common patterns and return penalty score"""
    penalty = 0
    password_lower = password.lower()

    # Common passwords and patterns
    common_passwords = [
        "password",
        "123456",
        "qwerty",
        "admin",
        "welcome",
        "letmein",
        "monkey",
        "password1",
        "12345678",
        "123456789",
    ]

    sequential_patterns = [
        "123",
        "234",
        "345",
        "456",
        "567",
        "678",
        "789",
        "abc",
        "bcd",
        "cde",
        "def",
        "efg",
        "fgh",
        "ghi",
        "qwe",
        "wer",
        "ert",
        "rty",
        "tyu",
        "yui",
        "uio",
        "iop",
    ]

    keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "123qwe"]

    # Check for common passwords
    for common in common_passwords:
        if common in password_lower:
            penalty += 10

    # Check for sequential patterns
    for pattern in sequential_patterns:
        if pattern in password_lower:
            penalty += 5

    # Check for keyboard patterns
    for pattern in keyboard_patterns:
        if pattern in password_lower:
            penalty += 8

    # Check for repeated characters
    if re.search(r"(.)\1{2,}", password):
        penalty += 5

    return min(penalty, 15)  # Max penalty of 15 points


def get_password_recommendations(password: str) -> list:
    """Get recommendations for improving password strength"""
    recommendations = []

    if len(password) < 12:
        recommendations.append("Use at least 12 characters")

    if not any(c.isupper() for c in password):
        recommendations.append("Add uppercase letters")

    if not any(c.islower() for c in password):
        recommendations.append("Add lowercase letters")

    if not any(c.isdigit() for c in password):
        recommendations.append("Add numbers")

    if not any(c in string.punctuation for c in password):
        recommendations.append("Add special characters (!@#$% etc.)")

    if check_common_patterns(password) > 0:
        recommendations.append("Avoid common patterns and sequences")

    return recommendations
