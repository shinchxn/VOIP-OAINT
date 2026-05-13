"""
Number Permutation Engine
Generates related/neighbor numbers used by scammers
to identify infrastructure clusters.
"""

import logging
from typing import Iterator
# pyrefly: ignore [missing-import]
import phonenumbers
# pyrefly: ignore [missing-import]
from phonenumbers import NumberParseException

log = logging.getLogger("number_permutator")


def generate_permutations(number: str, modes: list[str] = None) -> list[str]:
    """
    Generate variants of a given E.164 phone number.

    Modes:
        last_digit      — change final digit 0-9
        sequential      — ±10 neighbors
        last_two_digits — all combos for last 2 digits
        swap_area       — common area code swaps (US)

    Returns a deduplicated list of E.164 strings.
    """
    modes   = modes or ["last_digit", "sequential"]
    results = set()

    try:
        parsed = phonenumbers.parse(number)
    except NumberParseException as e:
        log.error(f"[Permutator] Could not parse {number}: {e}")
        return []

    cc   = parsed.country_code
    base = str(parsed.national_number)

    for mode in modes:
        for variant in _generate(cc, base, mode):
            results.add(variant)

    # Remove the original
    results.discard(f"+{cc}{base}")
    ordered = sorted(results)
    log.info(f"[Permutator] Generated {len(ordered)} variants for {number}")
    return ordered


def batch_check(
    numbers: list[str],
    check_fn,             # callable: number -> dict (e.g. hlr_lookup)
    workers: int = 5,
) -> list[dict]:
    """
    Run check_fn against all permutations in a thread pool.
    Useful for: check which variants are active VOIP lines.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_fn, n): n for n in numbers}
        for future in as_completed(futures):
            num = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                log.warning(f"[Permutator] Check failed for {num}: {e}")
    return results


# ── generators ───────────────────────────────────────────────

def _generate(cc: int, base: str, mode: str) -> Iterator[str]:
    prefix = f"+{cc}"
    n      = int(base)

    if mode == "last_digit":
        stem = base[:-1]
        for d in range(10):
            yield f"{prefix}{stem}{d}"

    elif mode == "sequential":
        for delta in range(-10, 11):
            candidate = str(n + delta).zfill(len(base))
            if len(candidate) == len(base):
                yield f"{prefix}{candidate}"

    elif mode == "last_two_digits":
        stem = base[:-2]
        for d in range(100):
            yield f"{prefix}{stem}{d:02d}"

    elif mode == "swap_area":
        # US area codes commonly used by VOIP scammers
        VOIP_AREA_CODES = [
            "202", "212", "310", "415", "646",
            "702", "800", "833", "844", "855", "866", "877", "888",
        ]
        if len(base) == 10:   # NANP format
            local = base[3:]
            for area in VOIP_AREA_CODES:
                yield f"{prefix}{area}{local}"
