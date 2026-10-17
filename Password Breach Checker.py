#Password Strength & Breach Checker makes use of HaveIBeenPwned's API.
#HaveIBeenPwned supports k-anonymity meaning that it doesnt send full passwords in one go and hashes them while you receive the parts of your passwords back unhashed.
#Your passwords are completely safe.


import argparse
import getpass
import hashlib
import math
import re
import string
import sys

import requests

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "monkey", "111111", "iloveyou", "admin", "welcome", "password1",
}


# ---------------------------------------------------------------------------
# Local strength scoring (no network required)
# ---------------------------------------------------------------------------

def calculate_entropy(password: str) -> float:
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[%s]" % re.escape(string.punctuation), password):
        pool_size += len(string.punctuation)

    if pool_size == 0 or len(password) == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def strength_label(entropy: float) -> str:
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Reasonable"
    elif entropy < 128:
        return "Strong"
    else:
        return "Very Strong"


def check_local_weaknesses(password: str) -> list[str]:
    """Flag obvious weak patterns beyond raw entropy."""
    warnings = []

    if password.lower() in COMMON_PASSWORDS:
        warnings.append("This is one of the most commonly used passwords in the world.")

    if len(password) < 8:
        warnings.append("Shorter than 8 characters -- easy to brute-force.")

    if re.fullmatch(r"[a-zA-Z]+", password):
        warnings.append("Letters only -- add numbers and symbols.")

    if re.fullmatch(r"[0-9]+", password):
        warnings.append("Digits only -- very easy to brute-force.")

    if re.search(r"(.)\1{2,}", password):
        warnings.append("Contains repeated characters (e.g. 'aaa').")

    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)", password.lower()):
        warnings.append("Contains a sequential pattern (e.g. '1234', 'abcd').")

    return warnings


# ---------------------------------------------------------------------------
# Breach check via HaveIBeenPwned (k-anonymity model)
# ---------------------------------------------------------------------------

def check_breach(password: str) -> int:
    """
    Check if a password has appeared in known breaches.

    Returns the number of times it's been seen (0 if not found).
    Raises requests.RequestException on network failure.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    response = requests.get(
        f"{HIBP_API_URL}{prefix}",
        headers={"Add-Padding": "true"},  # asks HIBP to pad response, extra privacy
        timeout=10,
    )
    response.raise_for_status()

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


# ---------------------------------------------------------------------------
# Command Line Interface
# ---------------------------------------------------------------------------

def analyze_password(password: str, skip_breach_check: bool = False) -> None:
    print("\n--- Password Analysis ---")

    entropy = calculate_entropy(password)
    label = strength_label(entropy)
    print(f"Length:        {len(password)} characters")
    print(f"Entropy:       {entropy:.1f} bits")
    print(f"Strength:      {label}")

    warnings = check_local_weaknesses(password)
    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  - {w}")

    if not skip_breach_check:
        print("\nChecking HaveIBeenPwned...")
        try:
            count = check_breach(password)
            if count > 0:
                print(f"  ⚠ Found in {count:,} known breaches. Do NOT use this password.")
            else:
                print("  ✔ Not found in any known breach.")
        except requests.RequestException as e:
            print(f"  Could not reach HaveIBeenPwned API: {e}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Check password strength and breach history."
    )
    parser.add_argument(
        "-p", "--password",
        help="Password to check (omit this flag to be prompted securely instead)",
    )
    parser.add_argument(
        "--no-breach-check",
        action="store_true",
        help="Skip the HaveIBeenPwned network check (local strength check only)",
    )
    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter password to check: ")

    if not password:
        print("No password provided.", file=sys.stderr)
        sys.exit(1)

    analyze_password(password, skip_breach_check=args.no_breach_check)


if __name__ == "__main__":
    main()
