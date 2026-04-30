# pip install bip-utils

"""
BIP39 / BIP84 Bitcoin Mnemonic Recovery Script

Purpose:
    Use this script when you know most of your BIP39 mnemonic words,
    but a small number of words are missing.

Supported recovery mode:
    Known words are entered normally.
    Unknown words are entered as "?".

Example:
    abandon abandon ? abandon abandon abandon abandon abandon abandon abandon abandon ?

Or:
    abandon, abandon, ?, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, ?

Candidate words:
    You may enter a candidate word list using spaces or commas.

Example:
    about above absent

Or:
    about, above, absent

If the candidate word list is left empty:
    The script will try all 2048 English BIP39 words for every "?" position.

What it does:
    1. Reads user input in a friendly format.
    2. Keeps asking again if the input is invalid.
    3. Validates known words against the English BIP39 word list.
    4. Replaces missing "?" positions with candidate words.
    5. Checks whether each completed mnemonic is valid using the BIP39 checksum.
    6. Derives Bitcoin BIP84 Native SegWit addresses.
    7. Compares derived addresses with the target bc1q address.

Network:
    This script is fully offline.
    It does not connect to the internet.
    It does not call blockchain explorers.
    It does not call remote APIs.
    It does not upload your mnemonic.
    It does not write results to local files.

Security:
    Use this only to recover your own wallet.
    Run it on an offline computer when working with real wallet data.
    If a match is found, the full mnemonic will be printed on the screen.

Default derivation path:
    m/84'/0'/0'/0/index

Address type:
    Bitcoin Native SegWit, usually starting with bc1q.
"""

from __future__ import annotations

import itertools
import re
import time
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


PROGRESS_INTERVAL = 100_000                 # Print progress every N checked combinations
LARGE_SEARCH_CONFIRM_LIMIT = 5_000_000      # Ask for confirmation if the search is larger than this


def read_until_valid(prompt: str, parser):
    """
    Keep asking the user until the parser returns a valid value.
    """

    while True:
        text = input(prompt).strip()         # Read user input

        try:
            return parser(text)              # Return parsed value if valid
        except ValueError as error:
            print()
            print(f"Input error: {error}")   # Show the reason instead of exiting
            print("Please try again.")
            print()


def parse_target_address(text: str) -> str:
    """
    Parse the target BTC address.
    """

    address = text.strip().lower()           # Normalize address text

    if not address:
        raise ValueError("target address cannot be empty")

    return address


def normalize_word(word: str) -> str:
    """
    Normalize one word token.
    """

    word = word.strip().lower()              # Remove spaces and lowercase the word

    if word == "？":
        return "?"                           # Accept Chinese question mark as unknown marker

    return word


def parse_words_line(text: str) -> list[str]:
    """
    Parse words from a friendly input line.

    Supported formats:
        word1 word2 word3
        word1, word2, word3
        word1，word2，word3
    """

    words = [
        normalize_word(word)
        for word in re.split(r"[\s,，]+", text.strip())   # Split by spaces, commas, or Chinese commas
        if word.strip()
    ]

    if not words:
        raise ValueError("word list cannot be empty")

    return words


def remove_duplicates_keep_order(words: list[str]) -> list[str]:
    """
    Remove duplicate words while preserving the original order.
    """

    seen = set()                              # Track words already seen
    result = []                               # Store unique words in original order

    for word in words:
        if word not in seen:
            seen.add(word)
            result.append(word)

    return result


def parse_mnemonic_template(text: str) -> list[str]:
    """
    Parse mnemonic template.

    Known words are normal BIP39 words.
    Unknown words are represented by "?".
    """

    words = parse_words_line(text)            # Parse space/comma separated input

    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError(
            f"mnemonic length must be 12, 15, 18, 21, or 24 words, "
            f"but you entered {len(words)}"
        )

    if "?" not in words:
        raise ValueError('the mnemonic template must contain at least one "?"')

    return words


def validate_mnemonic_template(
    mnemonic_words: list[str],
    bip39_words_set: set[str],
) -> list[str]:
    """
    Validate all known words in the mnemonic template.
    """

    invalid_words = [
        word
        for word in mnemonic_words
        if word != "?" and word not in bip39_words_set
    ]                                          # Unknown marker "?" is allowed

    if invalid_words:
        raise ValueError(f"invalid BIP39 words: {invalid_words}")

    return mnemonic_words


def read_mnemonic_template(bip39_words_set: set[str]) -> list[str]:
    """
    Read mnemonic template and retry until valid.
    """

    while True:
        text = input("Mnemonic template: ").strip()

        try:
            words = parse_mnemonic_template(text)
            return validate_mnemonic_template(words, bip39_words_set)
        except ValueError as error:
            print()
            print(f"Input error: {error}")
            print("Please enter the mnemonic template again.")
            print()


def parse_candidate_words(
    text: str,
    bip39_words: list[str],
    bip39_words_set: set[str],
) -> list[str]:
    """
    Parse candidate words.

    Empty input means all 2048 English BIP39 words will be used.
    """

    if not text.strip():
        return bip39_words                     # Empty input means try all BIP39 English words

    candidates = parse_words_line(text)         # Parse user candidate words
    candidates = remove_duplicates_keep_order(candidates)

    if "?" in candidates:
        raise ValueError('candidate words cannot contain "?"')

    invalid_words = [
        word
        for word in candidates
        if word not in bip39_words_set
    ]                                           # Candidate words must be valid BIP39 words

    if invalid_words:
        raise ValueError(f"invalid candidate BIP39 words: {invalid_words}")

    return candidates


def read_candidate_words(
    bip39_words: list[str],
    bip39_words_set: set[str],
) -> list[str]:
    """
    Read candidate words and retry until valid.
    """

    while True:
        text = input("Candidate words, or empty for all 2048 BIP39 words: ").strip()

        try:
            return parse_candidate_words(text, bip39_words, bip39_words_set)
        except ValueError as error:
            print()
            print(f"Input error: {error}")
            print("Please enter candidate words again, or press Enter for all words.")
            print()


def parse_non_negative_int(text: str, default: int) -> int:
    """
    Parse an integer that must be zero or greater.
    """

    if text == "":
        return default                           # Empty input uses default value

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
        return default                           # Empty input uses default value

    try:
        value = int(text)
    except ValueError:
        raise ValueError("please enter a valid integer")

    if value <= 0:
        raise ValueError("value must be greater than 0")

    return value


def read_yes_or_no(prompt: str) -> bool:
    """
    Read a yes/no answer.
    """

    while True:
        answer = input(prompt).strip().lower()

        if answer in ("y", "yes"):
            return True

        if answer in ("n", "no"):
            return False

        print("Please enter yes or no.")


def is_valid_mnemonic(mnemonic: str) -> bool:
    """
    Return True if the mnemonic is a valid English BIP39 mnemonic.
    """

    return Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic)


def build_receive_context(mnemonic: str, passphrase: str):
    """
    Build BIP84 Bitcoin receiving address context.
    """

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)      # Generate seed from mnemonic and passphrase

    return (
        Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)                 # Bitcoin mainnet BIP84 context
        .Purpose()                                                     # m/84'
        .Coin()                                                        # m/84'/0'
        .Account(0)                                                    # m/84'/0'/0'
        .Change(Bip44Changes.CHAIN_EXT)                                # m/84'/0'/0'/0
    )


def format_duration(seconds: float) -> str:
    """
    Format duration into a readable string.
    """

    minute = 60
    hour = 60 * minute
    day = 24 * hour
    year = 365 * day

    if seconds < minute:
        return f"{seconds:.2f} seconds"

    if seconds < hour:
        return f"{seconds / minute:.2f} minutes"

    if seconds < day:
        return f"{seconds / hour:.2f} hours"

    if seconds < year:
        return f"{seconds / day:.2f} days"

    years = seconds / year

    if years < 1_000:
        return f"{years:.2f} years"

    return f"{years:.2e} years"


print("=" * 70)
print("BIP39 / BIP84 Bitcoin Mnemonic Recovery Tool")
print("=" * 70)
print("Purpose      : recover missing mnemonic words")
print("Address type : Bitcoin Native SegWit, bc1q...")
print("Path         : m/84'/0'/0'/0/index")
print("Network      : fully offline")
print("=" * 70)
print()


target_address = read_until_valid(
    "Enter target BTC address, for example bc1q...: ",
    parse_target_address,
)

if not target_address.startswith("bc1q"):
    print()
    print("Warning: this script is designed for BIP84 bc1q addresses.")
    print("If your address starts with 1, 3, or bc1p, this script may not be suitable.")
    print()


words_list = Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH)

bip39_words = [
    words_list.GetWordAtIdx(index)
    for index in range(words_list.Length())
]

bip39_words_set = set(bip39_words)


print()
print("Enter your mnemonic template.")
print('Use "?" for each unknown word.')
print("You can separate words with spaces or commas.")
print()
print("Example:")
print("abandon abandon ? abandon abandon abandon abandon abandon abandon abandon abandon ?")
print()
print("Or:")
print("abandon, abandon, ?, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, ?")
print()

mnemonic_words = read_mnemonic_template(bip39_words_set)


print()
print("Enter candidate words for the unknown positions.")
print("The same candidate list will be used for every ? position.")
print("You can separate words with spaces or commas.")
print()
print("Example:")
print("about above absent")
print()
print("Or:")
print("about, above, absent")
print()
print("If you do not know the missing words, just press Enter.")
print("Then the script will try all 2048 English BIP39 words.")
print()

candidates = read_candidate_words(bip39_words, bip39_words_set)


print()

passphrase = getpass("BIP39 passphrase, or press Enter if none: ")

start_index = read_until_valid(
    "Enter start address index, default 0: ",
    lambda text: parse_non_negative_int(text, default=0),
)

address_count = read_until_valid(
    "Enter number of addresses to check, default 20: ",
    lambda text: parse_positive_int(text, default=20),
)


missing_positions = [
    index
    for index, word in enumerate(mnemonic_words)
    if word == "?"
]

total_combinations = len(candidates) ** len(missing_positions)


print()
print("=" * 70)
print("Exact search summary")
print("=" * 70)
print(f"Target address           : {target_address}")
print(f"Mnemonic length          : {len(mnemonic_words)}")
print(f"Unknown word count       : {len(missing_positions)}")
print(f"Unknown positions        : {[pos + 1 for pos in missing_positions]}")
print(f"Candidate word count     : {len(candidates)}")
print(f"Exact combinations       : {total_combinations:,}")
print(f"Address path             : m/84'/0'/0'/0/{start_index} ~ {start_index + address_count - 1}")
print("=" * 70)
print()


if total_combinations > LARGE_SEARCH_CONFIRM_LIMIT:
    print("Warning: this is a large search.")
    print(f"The script needs to check {total_combinations:,} combinations.")
    print("This may take a long time.")
    print()

    should_continue = read_yes_or_no("Continue? Type yes or no: ")

    if not should_continue:
        print("Stopped by user.")
        raise SystemExit(0)


input("Press Enter to start the search, or Ctrl+C to stop now.")


start_time = time.time()
checked_count = 0
valid_mnemonic_count = 0


for replacement_words in itertools.product(candidates, repeat=len(missing_positions)):
    checked_count += 1

    test_words = mnemonic_words.copy()                    # Copy template words

    for position, replacement_word in zip(missing_positions, replacement_words):
        test_words[position] = replacement_word            # Fill each unknown position

    mnemonic = " ".join(test_words)                        # Build full mnemonic text

    if not is_valid_mnemonic(mnemonic):
        if checked_count % PROGRESS_INTERVAL == 0:
            elapsed = max(time.time() - start_time, 0.000001)
            speed = checked_count / elapsed
            remaining = total_combinations - checked_count
            eta = remaining / speed

            print(
                f"Checked {checked_count:,} / {total_combinations:,}, "
                f"valid {valid_mnemonic_count:,}, "
                f"speed {speed:,.2f}/sec, "
                f"ETA {format_duration(eta)}"
            )

        continue                                           # Invalid checksum, skip address derivation

    valid_mnemonic_count += 1                              # Count valid BIP39 mnemonic
    receive_ctx = build_receive_context(mnemonic, passphrase)

    for address_index in range(start_index, start_index + address_count):
        address = receive_ctx.AddressIndex(address_index).PublicKey().ToAddress()

        if address == target_address:
            path = f"m/84'/0'/0'/0/{address_index}"

            print()
            print("=" * 70)
            print("Match found")
            print("=" * 70)
            print(f"Mnemonic   : {mnemonic}")
            print(f"Passphrase : {passphrase!r}")
            print(f"Path       : {path}")
            print(f"Address    : {address}")
            print("=" * 70)

            raise SystemExit(0)

    if checked_count % PROGRESS_INTERVAL == 0:
        elapsed = max(time.time() - start_time, 0.000001)
        speed = checked_count / elapsed
        remaining = total_combinations - checked_count
        eta = remaining / speed

        print(
            f"Checked {checked_count:,} / {total_combinations:,}, "
            f"valid {valid_mnemonic_count:,}, "
            f"speed {speed:,.2f}/sec, "
            f"ETA {format_duration(eta)}"
        )


elapsed = max(time.time() - start_time, 0.000001)

print()
print("=" * 70)
print("Search finished: no matching result found.")
print("=" * 70)
print("Possible reasons:")
print("1. The candidate word list does not contain the real missing word.")
print('2. The "?" positions are wrong.')
print("3. The target address was not generated from this mnemonic.")
print("4. The BIP39 passphrase is wrong.")
print("5. The address does not use the BIP84 path m/84'/0'/0'/0/index.")
print("6. The address index range is too small.")
print()
print(f"Total checked combinations : {checked_count:,}")
print(f"Valid BIP39 mnemonics      : {valid_mnemonic_count:,}")
print(f"Elapsed time               : {format_duration(elapsed)}")
print(f"Average speed              : {checked_count / elapsed:,.2f} combinations/sec")
print("=" * 70)
