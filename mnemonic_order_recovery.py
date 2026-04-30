# pip install bip-utils

"""
BIP39 / BIP84 Bitcoin Mnemonic Order Recovery Script

Purpose:
    Use this script when you remember all 12 or 24 BIP39 mnemonic words,
    but the word order is mixed up.

What it supports:
    1. Completely unknown word order.
    2. Known fixed word positions.

       Example:
           3=apple, 12=zoo

       Meaning:
           The 3rd word is apple.
           The 12th word is zoo.

    3. Known adjacent word groups.

       Example:
           apple banana; word8 word9 word10

       Meaning:
           "apple banana" must stay together in this exact order.
           "word8 word9 word10" must stay together in this exact order.
           Their final positions are still unknown.

What this script does:
    1. Reads user input in a friendly command-line format.
    2. Accepts spaces, English commas, and Chinese commas as separators.
    3. Keeps asking again if the user enters invalid input.
    4. Calculates the exact number of candidate orders before searching.
    5. Benchmarks local speed and estimates total running time.
    6. Checks whether each candidate order is a valid BIP39 mnemonic.
    7. Derives Bitcoin BIP84 Native SegWit receiving addresses.
    8. Compares each derived address with the target bc1q address.

Network behavior:
    This script is fully offline.
    It does not connect to the internet.
    It does not call blockchain explorers.
    It does not call remote APIs.
    It does not upload your mnemonic.
    It does not write recovery results to local files.

Security warning:
    Use this only to recover your own wallet.
    Run it on an offline computer when working with real wallet data.
    If a match is found, the full mnemonic will be printed on the screen.
    Do not run real mnemonic recovery on a cloud server, shared computer,
    remote desktop, or any environment you do not fully trust.

For anyone who has lost mnemonic order:
    If all words are known but the order is mixed up, recovery may still be very
    expensive. For 12 unique words, the full search space is 12! = 479,001,600
    orders. For 24 unique words, the full search space is 24!, which is normally
    not practical to brute force.

    Even small clues can reduce the search space dramatically. If you know that
    one word is fixed at a position, or that two words are adjacent, enter that
    information when prompted.

Default derivation path:
    m/84'/0'/0'/0/index

Address type:
    Bitcoin Native SegWit, usually starting with bc1q.
"""

from __future__ import annotations

import math
import re
import time
from collections import Counter
from functools import lru_cache
from getpass import getpass

from bip_utils import (
    Bip39Languages,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip44Changes,
    Bip84,
    Bip84Coins,
)

from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter


BENCHMARK_LIMIT = 10_000                 # Number of candidate orders used for speed estimation
PROGRESS_INTERVAL = 100_000              # Print progress every N checked candidate orders
KEEP_WINDOW_SLEEP_SECONDS = 60 * 60      # Sleep duration used to keep the console window open


def keep_window_open() -> None:
    """
    Keep the console window open after the script finishes.

    This is useful on Windows when the script is launched by double-clicking,
    because the console window would otherwise close immediately and hide the result.
    Press Ctrl+C to close the window.
    """

    print()
    print("The script has finished. Press Ctrl+C to close this window.")

    while True:
        time.sleep(KEEP_WINDOW_SLEEP_SECONDS)    # Keep the process alive without using CPU


def read_until_valid(prompt: str, parser):
    """
    Keep asking the user until the parser returns a valid value.
    """

    while True:
        text = input(prompt).strip()             # Read one input line and remove surrounding spaces

        try:
            return parser(text)                  # Return parsed value if validation succeeds
        except ValueError as error:
            print()
            print(f"Input error: {error}")      # Show the reason instead of exiting immediately
            print("Please try again.")
            print()


def parse_target_address(text: str) -> str:
    """
    Parse the target Bitcoin address.
    """

    address = text.strip().lower()               # Normalize address text

    if not address:
        raise ValueError("target address cannot be empty")

    return address


def parse_words_line(text: str) -> list[str]:
    """
    Parse words from a user-friendly input line.

    Supported formats:
        word1 word2 word3
        word1, word2, word3
        word1，word2，word3
    """

    words = [
        word.strip().lower()
        for word in re.split(r"[\s,，]+", text.strip())   # Split by whitespace, English comma, or Chinese comma
        if word.strip()
    ]

    if not words:
        raise ValueError("word list cannot be empty")

    return words


def parse_mnemonic_words(text: str) -> list[str]:
    """
    Parse unordered mnemonic words.
    """

    words = parse_words_line(text)               # Convert friendly input into a word list

    if len(words) not in (12, 24):
        raise ValueError(
            f"this script supports 12 or 24 words, but you entered {len(words)}"
        )

    return words


def validate_bip39_words(words: list[str], bip39_words_set: set[str]) -> list[str]:
    """
    Validate that all words exist in the English BIP39 word list.
    """

    invalid_words = [
        word
        for word in words
        if word not in bip39_words_set
    ]                                             # Collect words not found in the English BIP39 word list

    if invalid_words:
        raise ValueError(f"invalid BIP39 words: {invalid_words}")

    return words


def read_mnemonic_words(bip39_words_set: set[str]) -> list[str]:
    """
    Read mnemonic words and retry until the input is valid.
    """

    while True:
        text = input("Unordered mnemonic words: ").strip()    # Friendly input: spaces or commas are both accepted

        try:
            words = parse_mnemonic_words(text)                # Parse the word line
            return validate_bip39_words(words, bip39_words_set)
        except ValueError as error:
            print()
            print(f"Input error: {error}")
            print("Please enter the mnemonic words again.")
            print()


def parse_fixed_positions(text: str) -> dict[int, str]:
    """
    Parse fixed-position clues.

    Supported formats:
        3=apple, 12=zoo
        3:apple, 12:zoo
        3 apple, 12 zoo

    Empty input means no fixed-position clues.
    """

    if not text.strip():
        return {}                                  # Empty input means no fixed-position clues

    fixed_positions = {}                           # Store position -> word

    for item in re.split(r"[,，;；]+", text.strip()):   # Split multiple clues by comma or semicolon
        item = item.strip()

        if not item:
            continue

        match = re.match(r"^(\d+)\s*(?:=|:|\s)\s*([a-zA-Z]+)$", item)  # Accept 3=word, 3:word, or 3 word

        if not match:
            raise ValueError(
                f"invalid fixed-position format: {item}. "
                "Use format like: 3=apple, 12=zoo"
            )

        position = int(match.group(1))             # User-facing position starts from 1
        word = match.group(2).lower()              # Normalize word to lowercase

        if position in fixed_positions:
            raise ValueError(f"duplicate fixed position: {position}")

        fixed_positions[position] = word           # Save the fixed-position clue

    return fixed_positions


def validate_fixed_positions(
    fixed_positions: dict[int, str],
    word_count: int,
    bip39_words_set: set[str],
    mnemonic_counter: Counter,
) -> dict[int, str]:
    """
    Validate fixed-position clues.
    """

    fixed_word_counter = Counter(fixed_positions.values())   # Count fixed words to handle repeated mnemonic words

    for position, word in fixed_positions.items():
        if position < 1 or position > word_count:
            raise ValueError(f"fixed position out of range: {position}")

        if word not in bip39_words_set:
            raise ValueError(f"fixed word is not a valid BIP39 word: {word}")

    for word, count in fixed_word_counter.items():
        if count > mnemonic_counter[word]:
            raise ValueError(
                f"fixed word appears too many times: {word}. "
                f"Needed {count}, available {mnemonic_counter[word]}"
            )

    return fixed_positions


def read_fixed_positions(
    word_count: int,
    bip39_words_set: set[str],
    mnemonic_counter: Counter,
) -> dict[int, str]:
    """
    Read fixed-position clues and retry until valid.
    """

    while True:
        text = input("Fixed positions, or empty: ").strip()  # Example: 3=apple, 12=zoo

        try:
            fixed_positions = parse_fixed_positions(text)     # Parse user-friendly clue format

            return validate_fixed_positions(
                fixed_positions=fixed_positions,
                word_count=word_count,
                bip39_words_set=bip39_words_set,
                mnemonic_counter=mnemonic_counter,
            )
        except ValueError as error:
            print()
            print(f"Input error: {error}")
            print("Please enter fixed positions again, or press Enter for none.")
            print()


def parse_adjacent_groups(text: str) -> list[list[str]]:
    """
    Parse adjacent word group clues.

    Supported formats:
        apple banana
        apple, banana
        apple banana; zoo abandon about
        apple, banana; zoo, abandon, about

    Semicolon separates multiple groups.
    Empty input means no adjacent-group clues.
    """

    if not text.strip():
        return []                                   # Empty input means no adjacent groups

    groups = []                                     # Store groups such as [["apple", "banana"], ["zoo", "about"]]

    for group_text in re.split(r"[;；|]+", text.strip()):  # Semicolon or vertical bar separates groups
        group_words = parse_words_line(group_text)         # Parse words inside this group

        if len(group_words) < 2:
            raise ValueError(
                f"adjacent group must contain at least 2 words: {group_words}"
            )

        groups.append(group_words)                  # Save one adjacent group

    return groups


def validate_adjacent_groups(
    adjacent_groups: list[list[str]],
    bip39_words_set: set[str],
    available_counter: Counter,
) -> list[list[str]]:
    """
    Validate adjacent word group clues.
    """

    group_word_counter = Counter()                  # Count all words used by adjacent groups

    for group in adjacent_groups:
        for word in group:
            if word not in bip39_words_set:
                raise ValueError(f"group word is not a valid BIP39 word: {word}")

            group_word_counter[word] += 1           # Count group word usage

    for word, count in group_word_counter.items():
        if count > available_counter[word]:
            raise ValueError(
                f"group word appears too many times after fixed positions are used: {word}. "
                f"Needed {count}, available {available_counter[word]}"
            )

    return adjacent_groups


def read_adjacent_groups(
    bip39_words_set: set[str],
    available_counter: Counter,
) -> list[list[str]]:
    """
    Read adjacent group clues and retry until valid.
    """

    while True:
        text = input("Adjacent word groups, or empty: ").strip()  # Example: apple banana; zoo about

        try:
            adjacent_groups = parse_adjacent_groups(text)         # Parse user-friendly adjacent group format

            return validate_adjacent_groups(
                adjacent_groups=adjacent_groups,
                bip39_words_set=bip39_words_set,
                available_counter=available_counter,
            )
        except ValueError as error:
            print()
            print(f"Input error: {error}")
            print("Please enter adjacent groups again, or press Enter for none.")
            print()


def parse_non_negative_int(text: str, default: int) -> int:
    """
    Parse an integer that must be zero or greater.
    """

    if text == "":
        return default                               # Empty input uses the default value

    try:
        value = int(text)
    except ValueError:
        raise ValueError("please enter a valid integer")

    if value < 0:
        raise ValueError("value cannot be less than 0")

    return value


def parse_positive_int(text: str, default: int) -> int:
    """
    Parse an integer that must be greater than zero.
    """

    if text == "":
        return default                               # Empty input uses the default value

    try:
        value = int(text)
    except ValueError:
        raise ValueError("please enter a valid integer")

    if value <= 0:
        raise ValueError("value must be greater than 0")

    return value


def is_valid_mnemonic(words_or_text) -> bool:
    """
    Return True if the given word order is a valid BIP39 English mnemonic.
    """

    mnemonic = (
        " ".join(words_or_text)                     # Join list into text if input is a list
        if isinstance(words_or_text, list)
        else str(words_or_text)                     # Otherwise use text directly
    )

    return Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic)  # Check BIP39 checksum


def format_int(num: int) -> str:
    """
    Format an integer with comma separators.
    """

    return f"{num:,}"                                # Example: 1000000 -> 1,000,000


def format_duration(seconds: float) -> str:
    """
    Format duration into a readable string.
    """

    minute = 60                                      # Seconds in one minute
    hour = 60 * minute                               # Seconds in one hour
    day = 24 * hour                                  # Seconds in one day
    year = 365 * day                                 # Approximate seconds in one year

    if seconds < minute:
        return f"{seconds:.2f} seconds"

    if seconds < hour:
        return f"{seconds / minute:.2f} minutes"

    if seconds < day:
        return f"{seconds / hour:.2f} hours"

    if seconds < year:
        return f"{seconds / day:.2f} days"

    years = seconds / year                           # Convert very long duration to years

    if years < 1_000:
        return f"{years:.2f} years"

    return f"{years:.2e} years"


def factorial_permutation_count(unit_counter: Counter) -> int:
    """
    Count unique permutations of units.

    If all units are different:
        total = n!

    If some units repeat:
        total = n! / repeated_count!
    """

    total = math.factorial(sum(unit_counter.values()))       # Start with n! for all remaining units

    for count in unit_counter.values():
        total //= math.factorial(count)                      # Remove duplicate permutations

    return total


def count_candidate_orders(unit_counter: Counter, word_count: int, fixed_map: dict) -> int:
    """
    Count the exact number of candidate orders after applying clues.
    """

    all_units_are_single_words = all(
        len(unit) == 1
        for unit in unit_counter
    )                                                        # True if there are no adjacent groups

    if not fixed_map:
        return factorial_permutation_count(unit_counter)     # No fixed positions: simple unit permutation count

    if all_units_are_single_words:
        return factorial_permutation_count(unit_counter)     # Fixed words were removed, so direct count is exact

    unit_keys = tuple(unit_counter.keys())                   # Units to place: single words or adjacent groups
    fixed_positions = set(fixed_map)                         # Zero-based fixed positions
    start_counts = tuple(unit_counter[unit] for unit in unit_keys)  # Remaining quantity of each unit

    @lru_cache(maxsize=None)
    def count_from(position: int, counts: tuple[int, ...]) -> int:
        while position < word_count and position in fixed_positions:
            position += 1                                    # Skip fixed positions

        if position == word_count:
            return 1 if sum(counts) == 0 else 0              # Valid only if all units are used

        total = 0                                            # Count valid completions from this position

        for unit_index, unit in enumerate(unit_keys):
            if counts[unit_index] == 0:
                continue                                     # This unit has already been fully used

            end_position = position + len(unit)              # End position after placing this unit

            if end_position > word_count:
                continue                                     # Unit would exceed mnemonic length

            crosses_fixed_position = any(
                pos in fixed_positions
                for pos in range(position, end_position)
            )                                                # Check whether this unit would overlap fixed positions

            if crosses_fixed_position:
                continue                                     # Adjacent group cannot cover a fixed position

            next_counts = list(counts)                       # Copy counts before modifying
            next_counts[unit_index] -= 1                     # Consume one copy of this unit

            total += count_from(end_position, tuple(next_counts))  # Count all possible completions

        return total

    return count_from(0, start_counts)                       # Start counting from the first position


def unit_fits(current_words: list, position: int, unit: tuple[str, ...]) -> bool:
    """
    Check whether a unit can fit at the current position.
    """

    end_position = position + len(unit)                      # Position after placing this unit

    if end_position > len(current_words):
        return False                                         # Unit would exceed mnemonic length

    return all(
        current_words[pos] is None
        for pos in range(position, end_position)
    )                                                        # Unit fits only if all target slots are empty


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
        position += 1                                        # Skip already-filled positions

    if position == len(current_words):
        yield current_words.copy()                           # Emit one completed candidate order
        return

    for unit in unit_keys:
        if unit_counter[unit] <= 0:
            continue                                         # No remaining copy of this unit

        if not unit_fits(current_words, position, unit):
            continue                                         # Unit cannot fit here

        unit_counter[unit] -= 1                              # Use this unit once

        for offset, word in enumerate(unit):
            current_words[position + offset] = word          # Place the unit into the template

        yield from generate_candidate_orders(
            unit_counter=unit_counter,
            unit_keys=unit_keys,
            current_words=current_words,
            position=position + len(unit),
        )                                                    # Recursively fill remaining positions

        for offset in range(len(unit)):
            current_words[position + offset] = None          # Backtrack: remove the placed unit

        unit_counter[unit] += 1                              # Backtrack: restore the unit count


def build_receive_context(mnemonic: str, passphrase: str):
    """
    Build a BIP84 receiving-address derivation context.
    """

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)  # Generate seed from mnemonic and passphrase

    return (
        Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)             # Create Bitcoin mainnet BIP84 context
        .Purpose()                                                 # m/84'
        .Coin()                                                    # m/84'/0'
        .Account(0)                                                # m/84'/0'/0'
        .Change(Bip44Changes.CHAIN_EXT)                            # m/84'/0'/0'/0
    )


def build_search_units(
    mnemonic_words: list[str],
    fixed_positions: dict[int, str],
    adjacent_groups: list[list[str]],
) -> tuple[list, dict, Counter, tuple]:
    """
    Build the search template and permutation units from user clues.
    """

    word_count = len(mnemonic_words)                       # Total mnemonic length
    available_words = Counter(mnemonic_words)              # Count available input words
    template_words = [None] * word_count                   # Empty template, fixed words will be inserted here
    fixed_map = {}                                         # Zero-based fixed position map

    for position, word in fixed_positions.items():
        zero_based_position = position - 1                 # Convert user position to zero-based index

        template_words[zero_based_position] = word         # Place fixed word in template
        fixed_map[zero_based_position] = word              # Record fixed slot
        available_words[word] -= 1                         # Consume this fixed word

    block_units = []                                       # Adjacent groups are treated as indivisible blocks

    for group in adjacent_groups:
        for word in group:
            available_words[word] -= 1                     # Consume words used by adjacent groups

        block_units.append(tuple(group))                   # Store group as tuple so Counter can use it

    single_word_units = []                                 # Remaining words become single-word units

    for word, count in available_words.items():
        single_word_units.extend([(word,)] * count)        # Represent each single word as a one-word tuple

    unit_counter = Counter(block_units + single_word_units) # Count all units
    unit_keys = tuple(unit_counter.keys())                  # Stable unit order for generation

    return template_words, fixed_map, unit_counter, unit_keys


print("=" * 70)
print("BIP39 / BIP84 Bitcoin Mnemonic Order Recovery Tool")
print("=" * 70)
print("Purpose      : recover the correct word order")
print("Address type : Bitcoin Native SegWit, bc1q...")
print("Path         : m/84'/0'/0'/0/index")
print("Network      : fully offline")
print("=" * 70)
print()


target_address = read_until_valid(
    "Enter target BTC address, for example bc1q...: ",
    parse_target_address,
)                                                         # Read target address with retry

if not target_address.startswith("bc1q"):
    print()
    print("Warning: this script is designed for BIP84 bc1q addresses.")
    print("If your address starts with 1, 3, or bc1p, this script may not be suitable.")
    print()


words_list = Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH)  # Load English BIP39 word-list object

bip39_words = [
    words_list.GetWordAtIdx(index)
    for index in range(words_list.Length())
]                                                         # Convert BIP39 word-list object into a Python list

bip39_words_set = set(bip39_words)                        # Use set for fast word validation


print()
print("Enter all mnemonic words in any order.")
print("You can separate words with spaces or commas.")
print()
print("Example:")
print("abandon about ability able above absent absorb abstract absurd abuse access accident")
print()
print("Or:")
print("abandon, about, ability, able, above, absent, absorb, abstract, absurd, abuse, access, accident")
print()

mnemonic_words = read_mnemonic_words(bip39_words_set)     # Read unordered mnemonic words with retry
word_count = len(mnemonic_words)                          # Store mnemonic length
mnemonic_counter = Counter(mnemonic_words)                # Count input words, including duplicates


while True:
    print()
    print("Optional: enter fixed positions if you know exact word positions.")
    print("Position numbers start from 1.")
    print()
    print("Supported formats:")
    print("3=apple, 12=zoo")
    print("3:apple, 12:zoo")
    print("3 apple, 12 zoo")
    print()
    print("If you do not know any fixed positions, just press Enter.")
    print()

    fixed_positions = read_fixed_positions(
        word_count=word_count,
        bip39_words_set=bip39_words_set,
        mnemonic_counter=mnemonic_counter,
    )                                                       # Read fixed-position clues with retry

    available_after_fixed = mnemonic_counter.copy()         # Start from all mnemonic words

    for fixed_word in fixed_positions.values():
        available_after_fixed[fixed_word] -= 1              # Remove words already used by fixed positions

    print()
    print("Optional: enter adjacent word groups if you know some words are consecutive.")
    print("Each group must stay together in exactly the given order.")
    print("Use semicolon ; to separate multiple groups.")
    print()
    print("Supported formats:")
    print("apple banana")
    print("apple, banana")
    print("apple banana; zoo abandon about")
    print()
    print("If you do not know any adjacent groups, just press Enter.")
    print()

    adjacent_groups = read_adjacent_groups(
        bip39_words_set=bip39_words_set,
        available_counter=available_after_fixed,
    )                                                       # Read adjacent-group clues with retry

    template_words, fixed_map, unit_counter, unit_keys = build_search_units(
        mnemonic_words=mnemonic_words,
        fixed_positions=fixed_positions,
        adjacent_groups=adjacent_groups,
    )                                                       # Build fixed template and search units

    total_candidates = count_candidate_orders(
        unit_counter=unit_counter,
        word_count=word_count,
        fixed_map=fixed_map,
    )                                                       # Calculate exact candidate count

    if total_candidates > 0:
        break                                               # Clues are usable, continue to next step

    print()
    print("Clue error: no candidate orders are possible with the given clues.")
    print("Please enter the clues again.")
    print()


print()

passphrase = getpass("BIP39 passphrase, or press Enter if none: ")  # Hidden input for optional BIP39 passphrase

start_index = read_until_valid(
    "Enter start address index, default 0: ",
    lambda text: parse_non_negative_int(text, default=0),
)                                                               # Read start index with retry

address_count = read_until_valid(
    "Enter number of addresses to check, default 20: ",
    lambda text: parse_positive_int(text, default=20),
)                                                               # Read address count with retry


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

benchmark_start = time.time()                              # Benchmark start time
benchmark_checked = 0                                      # Number of benchmarked candidates
benchmark_valid = 0                                        # Number of valid BIP39 candidates during benchmark
benchmark_limit = min(BENCHMARK_LIMIT, total_candidates)   # Do not benchmark more than total candidates

for candidate_words in generate_candidate_orders(
    unit_counter=unit_counter.copy(),                      # Copy so benchmark does not affect full search
    unit_keys=unit_keys,
    current_words=template_words.copy(),                   # Copy template for benchmark
    position=0,
):
    benchmark_checked += 1                                 # Count one benchmark candidate

    mnemonic = " ".join(candidate_words)                    # Convert candidate words to mnemonic text

    if is_valid_mnemonic(mnemonic):
        benchmark_valid += 1                               # Count valid BIP39 mnemonic

        receive_ctx = build_receive_context(mnemonic, passphrase)  # Build derivation context only for valid mnemonics

        for address_index in range(start_index, start_index + address_count):
            receive_ctx.AddressIndex(address_index).PublicKey().ToAddress()    # Include address derivation cost in benchmark

    if benchmark_checked >= benchmark_limit:
        break                                              # Stop benchmark after enough samples

benchmark_elapsed = max(time.time() - benchmark_start, 0.000001)  # Avoid division by zero
speed = benchmark_checked / benchmark_elapsed                     # Estimated orders per second
estimated_seconds = total_candidates / speed                      # Estimated full search duration

print(f"Benchmark checked orders : {format_int(benchmark_checked)}")
print(f"Valid BIP39 mnemonics    : {format_int(benchmark_valid)}")
print(f"Estimated speed          : {speed:,.2f} orders/sec")
print(f"Estimated total time     : {format_duration(estimated_seconds)}")
print("=" * 70)
print()

input("Press Enter to start full search, or Ctrl+C to stop now.")


search_start = time.time()                                # Full search start time
checked_count = 0                                          # Total checked candidates
valid_count = 0                                            # Total valid BIP39 mnemonics

for candidate_words in generate_candidate_orders(
    unit_counter=unit_counter,
    unit_keys=unit_keys,
    current_words=template_words.copy(),
    position=0,
):
    checked_count += 1                                     # Count one candidate order

    mnemonic = " ".join(candidate_words)                    # Convert candidate order to mnemonic text

    if not is_valid_mnemonic(mnemonic):
        if checked_count % PROGRESS_INTERVAL == 0:
            elapsed = max(time.time() - search_start, 0.000001)  # Elapsed search time
            current_speed = checked_count / elapsed              # Current average speed
            remaining = total_candidates - checked_count          # Remaining candidate orders
            eta = remaining / current_speed                       # Estimated remaining time

            print(
                f"Checked {checked_count:,} / {total_candidates:,}, "
                f"valid {valid_count:,}, "
                f"speed {current_speed:,.2f}/sec, "
                f"ETA {format_duration(eta)}"
            )

        continue                                           # Invalid checksum, skip address derivation

    valid_count += 1                                       # Count valid BIP39 mnemonic
    receive_ctx = build_receive_context(mnemonic, passphrase)  # Build receiving context from valid mnemonic

    for address_index in range(start_index, start_index + address_count):
        address = receive_ctx.AddressIndex(address_index).PublicKey().ToAddress()  # Derive one bc1q address

        if address == target_address:
            path = f"m/84'/0'/0'/0/{address_index}"       # Matching derivation path

            print()
            print("=" * 70)
            print("Match found")
            print("=" * 70)
            print(f"Mnemonic   : {mnemonic}")
            print(f"Passphrase : {passphrase!r}")
            print(f"Path       : {path}")
            print(f"Address    : {address}")
            print("=" * 70)

            keep_window_open()

    if checked_count % PROGRESS_INTERVAL == 0:
        elapsed = max(time.time() - search_start, 0.000001)    # Elapsed search time
        current_speed = checked_count / elapsed                # Current average speed
        remaining = total_candidates - checked_count            # Remaining candidate orders
        eta = remaining / current_speed                         # Estimated remaining time

        print(
            f"Checked {checked_count:,} / {total_candidates:,}, "
            f"valid {valid_count:,}, "
            f"speed {current_speed:,.2f}/sec, "
            f"ETA {format_duration(eta)}"
        )


elapsed = max(time.time() - search_start, 0.000001)       # Total elapsed time

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

keep_window_open()
