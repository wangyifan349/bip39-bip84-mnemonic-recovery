# pip install bip-utils

"""
BIP39 / BIP84 Bitcoin Mnemonic Order Recovery Script

Purpose:
    Use this script when you remember all 12 or 24 BIP39 mnemonic words,
    but the word order is mixed up.

What it supports:
    1. Completely unknown word order.
    2. Known fixed positions, such as:
           {3: "apple", 12: "zoo"}

    3. Known adjacent word groups, such as:
           [["word1", "word2"], ["word8", "word9", "word10"]]

       This means those words must appear next to each other in exactly
       the given order, but their final position is unknown.

What it does:
    1. Calculates the exact number of candidate orders before starting.
    2. Benchmarks local speed and estimates total running time.
    3. Checks whether each candidate order is a valid BIP39 mnemonic.
    4. Derives Bitcoin BIP84 Native SegWit addresses.
    5. Compares derived addresses with your target bc1q address.

Network:
    This script is fully offline.
    It does not connect to the internet.
    It does not call blockchain explorers.
    It does not call remote APIs.
    It does not upload your mnemonic.
    It does not write results to local files.

Important:
    Use this only to recover your own wallet.
"""

import ast
import math
import time
from collections import Counter
from functools import lru_cache
from getpass import getpass

from bip_utils import (
    Bip39Languages,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip39WordsListGetter,
    Bip44Changes,
    Bip84,
    Bip84Coins,
)


BENCHMARK_LIMIT = 10_000          # Number of candidate orders used for speed estimation
PROGRESS_INTERVAL = 100_000       # Print progress every N checked candidate orders


def is_valid_mnemonic(words_or_text) -> bool:
    """
    Return True if the given word order is a valid BIP39 English mnemonic.
    """

    mnemonic = (
        " ".join(words_or_text)   # Join a word list into a mnemonic string
        if isinstance(words_or_text, list)
        else str(words_or_text)   # Use the input directly if it is already text
    )

    return Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic)  # Check BIP39 checksum validity


def format_int(num: int) -> str:
    return f"{num:,}"             # Format large integers with comma separators


def format_duration(seconds: float) -> str:
    minute = 60                   # Seconds in one minute
    hour = 60 * minute            # Seconds in one hour
    day = 24 * hour               # Seconds in one day
    year = 365 * day              # Approximate seconds in one year

    if seconds < minute:
        return f"{seconds:.2f} seconds"

    if seconds < hour:
        return f"{seconds / minute:.2f} minutes"

    if seconds < day:
        return f"{seconds / hour:.2f} hours"

    if seconds < year:
        return f"{seconds / day:.2f} days"

    years = seconds / year        # Convert very long durations to years
    return f"{years:.2f} years" if years < 1_000 else f"{years:.2e} years"


def factorial_permutation_count(unit_counter: Counter) -> int:
    """
    Count permutations of units.

    Unit examples:
        ("apple",)
        ("apple", "banana")
    """

    total = math.factorial(sum(unit_counter.values()))  # Start with n! for all units

    for count in unit_counter.values():
        total //= math.factorial(count)                 # Divide by duplicate unit counts

    return total


def count_candidate_orders(unit_counter: Counter, word_count: int, fixed_map: dict) -> int:
    """
    Count the exact number of candidate orders after applying clues.

    Clues:
        1. Fixed positions
        2. Adjacent word groups
        3. Duplicate words
    """

    all_units_are_single_words = all(len(unit) == 1 for unit in unit_counter)  # True when no adjacent groups exist

    if not fixed_map:
        return factorial_permutation_count(unit_counter)                      # No fixed positions: use direct formula

    if all_units_are_single_words:
        return factorial_permutation_count(unit_counter)                      # Only single words: use direct formula

    unit_keys = tuple(unit_counter.keys())                                    # Units to place: single words or adjacent groups
    fixed_positions = set(fixed_map)                                          # Positions already occupied by fixed words
    start_counts = tuple(unit_counter[unit] for unit in unit_keys)            # Remaining count for each unit

    @lru_cache(maxsize=None)                                                   # Cache repeated counting states
    def count_from(position: int, counts: tuple[int, ...]) -> int:
        while position < word_count and position in fixed_positions:
            position += 1                                                      # Skip fixed positions

        if position == word_count:
            return 1 if sum(counts) == 0 else 0                                # Valid only if all units have been used

        total = 0                                                              # Accumulate valid orders from this position

        for unit_index, unit in enumerate(unit_keys):
            if counts[unit_index] == 0:
                continue                                                       # Skip units that are already used up

            end_position = position + len(unit)                                # End position after placing this unit

            if end_position > word_count:
                continue                                                       # Unit does not fit inside mnemonic length

            crosses_fixed_position = any(
                pos in fixed_positions
                for pos in range(position, end_position)
            )                                                                  # Check whether the unit would overwrite a fixed position

            if crosses_fixed_position:
                continue                                                       # Do not place a unit over fixed positions

            next_counts = list(counts)                                         # Copy remaining counts
            next_counts[unit_index] -= 1                                       # Consume this unit once

            total += count_from(end_position, tuple(next_counts))              # Count the remaining positions recursively

        return total

    return count_from(0, start_counts)                                         # Start counting from position 0


def unit_fits(current_words: list, position: int, unit: tuple[str, ...]) -> bool:
    end_position = position + len(unit)                                        # Position after the unit is placed

    if end_position > len(current_words):
        return False                                                           # Unit would exceed mnemonic length

    return all(
        current_words[pos] is None
        for pos in range(position, end_position)
    )                                                                          # Unit fits only if all target slots are empty


def generate_candidate_orders(
    unit_counter: Counter,
    unit_keys: tuple,
    current_words: list,
    position: int,
):
    """
    Generate candidate mnemonic orders without storing all permutations in memory.
    """

    while position < len(current_words) and current_words[position] is not None:
        position += 1                                                          # Skip already-filled positions

    if position == len(current_words):
        yield current_words.copy()                                             # All positions filled: emit one candidate order
        return

    for unit in unit_keys:
        if unit_counter[unit] <= 0:
            continue                                                           # Skip units with no remaining copies

        if not unit_fits(current_words, position, unit):
            continue                                                           # Skip units that cannot fit here

        unit_counter[unit] -= 1                                                 # Use this unit once

        for offset, word in enumerate(unit):
            current_words[position + offset] = word                            # Place the unit into the current word array

        yield from generate_candidate_orders(
            unit_counter,
            unit_keys,
            current_words,
            position + len(unit),
        )                                                                      # Continue generating the rest of the order

        for offset in range(len(unit)):
            current_words[position + offset] = None                            # Backtrack: remove the placed unit

        unit_counter[unit] += 1                                                 # Backtrack: restore the unit count


def build_receive_context(mnemonic: str, passphrase: str):
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)             # Generate seed from mnemonic and BIP39 passphrase

    return (
        Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)                         # Create Bitcoin BIP84 context from seed
        .Purpose()                                                             # Derivation level: m/84'
        .Coin()                                                                # Derivation level: m/84'/0'
        .Account(0)                                                            # Derivation level: m/84'/0'/0'
        .Change(Bip44Changes.CHAIN_EXT)                                        # Derivation level: m/84'/0'/0'/0
    )


print("=" * 70)
print("BIP39 / BIP84 Bitcoin Mnemonic Order Recovery Tool")
print("=" * 70)
print("Purpose      : recover the correct word order")
print("Address type : Bitcoin Native SegWit, bc1q...")
print("Path         : m/84'/0'/0'/0/index")
print("Network      : fully offline")
print("=" * 70)
print()


target_address = input("Enter target BTC address, for example bc1q...: ").strip()

if not target_address:
    raise ValueError("Target address cannot be empty.")

if not target_address.startswith("bc1q"):
    print()
    print("Warning: this script is designed for BIP84 bc1q addresses.")
    print("If your address starts with 1, 3, or bc1p, this script may not be suitable.")
    print()


print()
print("Enter all mnemonic words as a Python list.")
print("The order may be wrong, but the words themselves must be correct.")
print()
print("Example:")
print('["abandon", "about", "ability", "able", "above", "absent",')
print(' "absorb", "abstract", "absurd", "abuse", "access", "accident"]')
print()

mnemonic_words = ast.literal_eval(input("Unordered mnemonic word list: ").strip())  # Parse the user-provided Python list

if not isinstance(mnemonic_words, list):
    raise ValueError("Mnemonic words must be provided as a list.")

mnemonic_words = [
    str(word).strip().lower()
    for word in mnemonic_words
]                                                                                  # Normalize words: strip spaces and lowercase

word_count = len(mnemonic_words)                                                   # Mnemonic length, usually 12 or 24

if word_count not in (12, 24):
    raise ValueError(f"This script supports 12 or 24 words. You entered {word_count}.")


words_list = Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH)           # Get the English BIP39 word-list object

bip39_words = [
    words_list.GetWordAtIdx(index)
    for index in range(words_list.Length())
]                                                                                  # Convert the word-list object into a Python list

bip39_words_set = set(bip39_words)                                                  # Convert to set for fast membership checks

invalid_words = [
    word
    for word in mnemonic_words
    if word not in bip39_words_set
]                                                                                  # Collect words that are not valid BIP39 English words

if invalid_words:
    raise ValueError(f"Invalid BIP39 words: {invalid_words}")


print()
print("Optional: enter fixed positions if you know exact word positions.")
print("Position numbers start from 1.")
print()
print("Example:")
print('{3: "apple", 12: "zoo"}')
print()
print("If you do not know any fixed positions, just press Enter.")
print()

fixed_input = input("Fixed positions, or empty: ").strip()
fixed_positions = ast.literal_eval(fixed_input) if fixed_input else {}              # Empty input means no fixed-position clues

if not isinstance(fixed_positions, dict):
    raise ValueError("Fixed positions must be a dictionary.")


print()
print("Optional: enter adjacent word groups if you know some words are consecutive.")
print("Each group must stay together in exactly the given order.")
print()
print("Example:")
print('[["word1", "word2"], ["word8", "word9", "word10"]]')
print()
print("If you do not know any adjacent groups, just press Enter.")
print()

groups_input = input("Adjacent word groups, or empty: ").strip()
adjacent_groups = ast.literal_eval(groups_input) if groups_input else []            # Empty input means no adjacent-group clues

if not isinstance(adjacent_groups, list):
    raise ValueError("Adjacent groups must be a list.")


print()

passphrase = getpass("BIP39 passphrase, or press Enter if none: ")                  # Optional BIP39 passphrase

start_index = int(input("Enter start address index, default 0: ").strip() or "0")   # First address index to check
address_count = int(input("Enter number of addresses to check, default 20: ").strip() or "20")  # Number of indexes to check

if start_index < 0:
    raise ValueError("Start index cannot be less than 0.")

if address_count <= 0:
    raise ValueError("Address count must be greater than 0.")


available_words = Counter(mnemonic_words)                                          # Count how many times each input word appears
template_words = [None] * word_count                                                # Empty mnemonic template
fixed_map = {}                                                                      # Fixed positions using zero-based indexes

for position, word in fixed_positions.items():
    position = int(position)                                                        # User positions are one-based
    word = str(word).strip().lower()                                                 # Normalize the fixed word

    if position < 1 or position > word_count:
        raise ValueError(f"Fixed position out of range: {position}")

    if word not in bip39_words_set:
        raise ValueError(f"Fixed word is not a valid BIP39 word: {word}")

    if available_words[word] <= 0:
        raise ValueError(f"Fixed word is not available in the input words: {word}")

    zero_based_position = position - 1                                               # Convert to zero-based index

    template_words[zero_based_position] = word                                       # Place the fixed word into the template
    fixed_map[zero_based_position] = word                                            # Record the fixed position
    available_words[word] -= 1                                                       # Mark this word as used once


block_units = []                                                                     # Adjacent groups treated as indivisible units

for group in adjacent_groups:
    if not isinstance(group, list):
        raise ValueError("Each adjacent group must be a list of words.")

    group = [
        str(word).strip().lower()
        for word in group
    ]                                                                                # Normalize words in the adjacent group

    if len(group) < 2:
        raise ValueError(f"Adjacent group must contain at least 2 words: {group}")

    for word in group:
        if word not in bip39_words_set:
            raise ValueError(f"Group word is not a valid BIP39 word: {word}")

        if available_words[word] <= 0:
            raise ValueError(
                f"Group word is not available after fixed positions are used: {word}"
            )

        available_words[word] -= 1                                                   # Mark this group word as used

    block_units.append(tuple(group))                                                 # Store the adjacent group as a tuple


single_word_units = []                                                               # Remaining words treated as single-word units

for word, count in available_words.items():
    single_word_units.extend([(word,)] * count)                                      # Convert each remaining word into a one-word tuple

unit_counter = Counter(block_units + single_word_units)                              # Count all units: groups and single words
unit_keys = tuple(unit_counter.keys())                                               # Stable unit list for generation

total_candidates = count_candidate_orders(
    unit_counter=unit_counter,
    word_count=word_count,
    fixed_map=fixed_map,
)                                                                                    # Exact number of candidate orders after applying clues

if total_candidates == 0:
    raise ValueError("No candidate orders are possible with the given clues.")


print()
print("=" * 70)
print("Exact search summary")
print("=" * 70)
print(f"Target address           : {target_address}")
print(f"Word count               : {word_count}")
print(f"Fixed positions          : {fixed_positions}")
print(f"Adjacent groups          : {adjacent_groups}")
print(f"Exact candidate orders   : {format_int(total_candidates)}")
print(f"Address path             : m/84'/0'/0'/0/{start_index} ~ {start_index + address_count - 1}")
print("=" * 70)
print()

print("Scale reference:")
print(f"12! = {format_int(math.factorial(12))}")
print(f"24! = {format_int(math.factorial(24))}")
print()


print("=" * 70)
print("Benchmarking")
print("=" * 70)

benchmark_start = time.time()                                                        # Benchmark start time
benchmark_checked = 0                                                                # Number of orders checked during benchmark
benchmark_valid = 0                                                                  # Number of valid BIP39 mnemonics during benchmark
benchmark_limit = min(BENCHMARK_LIMIT, total_candidates)                             # Do not benchmark more than total candidates

for candidate_words in generate_candidate_orders(
    unit_counter=unit_counter.copy(),                                                # Copy so benchmark does not affect full search
    unit_keys=unit_keys,
    current_words=template_words.copy(),                                             # Copy the template for benchmark
    position=0,
):
    benchmark_checked += 1                                                           # Count one benchmark candidate

    mnemonic = " ".join(candidate_words)                                              # Convert candidate words into mnemonic text

    if is_valid_mnemonic(mnemonic):
        benchmark_valid += 1                                                         # Count valid BIP39 mnemonic candidates

        receive_ctx = build_receive_context(mnemonic, passphrase)                    # Derive only after checksum passes

        for address_index in range(start_index, start_index + address_count):
            receive_ctx.AddressIndex(address_index).PublicKey().ToAddress()          # Include address derivation cost in benchmark

    if benchmark_checked >= benchmark_limit:
        break                                                                        # Stop benchmark after enough samples

benchmark_elapsed = max(time.time() - benchmark_start, 0.000001)                     # Avoid division by zero
speed = benchmark_checked / benchmark_elapsed                                        # Estimated orders per second
estimated_seconds = total_candidates / speed                                         # Estimated full search duration

print(f"Benchmark checked orders : {format_int(benchmark_checked)}")
print(f"Valid BIP39 mnemonics    : {format_int(benchmark_valid)}")
print(f"Estimated speed          : {speed:,.2f} orders/sec")
print(f"Estimated total time     : {format_duration(estimated_seconds)}")
print("=" * 70)
print()

input("Press Enter to start full search, or Ctrl+C to stop now.")


search_start = time.time()                                                           # Full search start time
checked_count = 0                                                                    # Total checked candidate orders
valid_count = 0                                                                      # Total valid BIP39 mnemonic candidates

for candidate_words in generate_candidate_orders(
    unit_counter=unit_counter,
    unit_keys=unit_keys,
    current_words=template_words.copy(),
    position=0,
):
    checked_count += 1                                                               # Count one candidate order

    mnemonic = " ".join(candidate_words)                                              # Convert candidate order to mnemonic text

    if not is_valid_mnemonic(mnemonic):
        if checked_count % PROGRESS_INTERVAL == 0:
            elapsed = max(time.time() - search_start, 0.000001)                      # Elapsed full-search time
            current_speed = checked_count / elapsed                                  # Current average speed
            remaining = total_candidates - checked_count                              # Remaining candidate orders
            eta = remaining / current_speed                                           # Estimated remaining time

            print(
                f"Checked {checked_count:,} / {total_candidates:,}, "
                f"valid {valid_count:,}, "
                f"speed {current_speed:,.2f}/sec, "
                f"ETA {format_duration(eta)}"
            )

        continue                                                                      # Invalid checksum: skip address derivation

    valid_count += 1                                                                  # Count a valid BIP39 mnemonic
    receive_ctx = build_receive_context(mnemonic, passphrase)                         # Build BIP84 context from the valid mnemonic

    for address_index in range(start_index, start_index + address_count):
        address = receive_ctx.AddressIndex(address_index).PublicKey().ToAddress()     # Derive one bc1q address

        if address == target_address:
            path = f"m/84'/0'/0'/0/{address_index}"                                  # Matching derivation path

            print()
            print("=" * 70)
            print("Match found")
            print("=" * 70)
            print(f"Mnemonic   : {mnemonic}")
            print(f"Passphrase : {passphrase!r}")
            print(f"Path       : {path}")
            print(f"Address    : {address}")
            print("=" * 70)

            raise SystemExit(0)                                                       # Exit immediately after a match is found

    if checked_count % PROGRESS_INTERVAL == 0:
        elapsed = max(time.time() - search_start, 0.000001)                          # Elapsed full-search time
        current_speed = checked_count / elapsed                                      # Current average speed
        remaining = total_candidates - checked_count                                  # Remaining candidate orders
        eta = remaining / current_speed                                               # Estimated remaining time

        print(
            f"Checked {checked_count:,} / {total_candidates:,}, "
            f"valid {valid_count:,}, "
            f"speed {current_speed:,.2f}/sec, "
            f"ETA {format_duration(eta)}"
        )


elapsed = max(time.time() - search_start, 0.000001)                                  # Total full-search elapsed time

print()
print("=" * 70)
print("Search finished: no matching result found.")
print("=" * 70)
print("Possible reasons:")
print("1. One or more words are wrong.")
print("2. One or more clues are wrong.")
print("3. The target address was not generated from this mnemonic.")
print("4. The BIP39 passphrase is wrong.")
print("5. The wallet does not use BIP84 m/84'/0'/0'/0/index.")
print("6. The address index range is too small.")
print()
print(f"Total checked orders : {checked_count:,}")
print(f"Valid BIP39 mnemonics: {valid_count:,}")
print(f"Elapsed time         : {format_duration(elapsed)}")
print(f"Average speed        : {checked_count / elapsed:,.2f} orders/sec")
print("=" * 70)
