# pip install bip-utils

"""
BIP39 / BIP84 Bitcoin Mnemonic Recovery Script

Purpose:
    Use this script when you know most of your BIP39 mnemonic words,
    but a small number of words are missing.

Recovery model:
    Known words are entered normally.
    Unknown words are entered as a question mark "?".

    Example:
        abandon abandon ? abandon abandon abandon abandon abandon abandon abandon abandon ?

    Or:
        abandon, abandon, ?, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, ?

Candidate words:
    You may enter a short candidate word list if you remember possible missing words.

    Example:
        about above absent

    Or:
        about, above, absent

    If the candidate word list is left empty, the script will try all 2048 English
    BIP39 words for every unknown "?" position.

What this script does:
    1. Reads user input in a friendly command-line format.
    2. Accepts spaces, English commas, and Chinese commas as separators.
    3. Keeps asking again if the input is invalid instead of exiting immediately.
    4. Validates known words against the English BIP39 word list.
    5. Replaces each "?" with candidate words.
    6. Checks each completed mnemonic using the BIP39 checksum.
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

For anyone who has lost mnemonic words:
    Losing mnemonic words is stressful and painful. That pressure is understandable.
    But it is also important to be honest: this kind of problem is usually caused
    by careless backup or storage practices, not by a blockchain failure.

    A mnemonic is effectively the final control key to the wallet assets. Once it
    is lost, leaked, written incorrectly, or stored in the wrong order, the assets
    may become permanently unrecoverable or may be taken by someone else.

    If you recover your wallet successfully, treat it as a serious lesson. Back up
    the mnemonic offline, clearly, accurately, redundantly, and store it in a secure
    physical location. Do not rely only on screenshots, cloud storage, chat history,
    browser notes, or a single electronic copy.

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
LARGE_SEARCH_CONFIRM_LIMIT = 5_000_000      # Ask before starting if the search space is larger than this
KEEP_WINDOW_SLEEP_SECONDS = 60 * 60         # Sleep duration used to keep the console window open


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

    The parser must either return a parsed value or raise ValueError with a clear
    user-facing message.
    """

    while True:
        text = input(prompt).strip()             # Read one input line and remove surrounding spaces

        try:
            return parser(text)                  # Return parsed value if validation succeeds
        except ValueError as error:
            print()
            print(f"Input error: {error}")      # Show the problem instead of exiting immediately
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


def normalize_word(word: str) -> str:
    """
    Normalize a single word token.
    """

    word = word.strip().lower()                  # Remove spaces and use lowercase

    if word == "？":
        return "?"                               # Accept Chinese question mark as an unknown marker

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
        for word in re.split(r"[\s,，]+", text.strip())   # Split by whitespace, English comma, or Chinese comma
        if word.strip()
    ]

    if not words:
        raise ValueError("word list cannot be empty")

    return words


def remove_duplicates_keep_order(words: list[str]) -> list[str]:
    """
    Remove duplicate words while preserving their first-seen order.
    """

    seen = set()                                  # Track words already added
    result = []                                   # Store unique words in the original order

    for word in words:
        if word not in seen:
            seen.add(word)                        # Mark this word as seen
            result.append(word)                   # Keep the first occurrence

    return result


def parse_mnemonic_template(text: str) -> list[str]:
    """
    Parse the mnemonic template.

    Known words are normal BIP39 words.
    Unknown words are represented by "?".
    """

    words = parse_words_line(text)                # Convert user-friendly input into a word list

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
    ]                                             # Unknown marker "?" is allowed; all other words must be BIP39 words

    if invalid_words:
        raise ValueError(f"invalid BIP39 words: {invalid_words}")

    return mnemonic_words


def read_mnemonic_template(bip39_words_set: set[str]) -> list[str]:
    """
    Read the mnemonic template and retry until it is valid.
    """

    while True:
        text = input("Mnemonic template: ").strip()   # Friendly input, no Python list syntax required

        try:
            words = parse_mnemonic_template(text)      # Parse known words and ? positions
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
        return bip39_words                         # Empty input means try every English BIP39 word

    candidates = parse_words_line(text)            # Parse space/comma separated candidate words
    candidates = remove_duplicates_keep_order(candidates)

    if "?" in candidates:
        raise ValueError('candidate words cannot contain "?"')

    invalid_words = [
        word
        for word in candidates
        if word not in bip39_words_set
    ]                                             # Candidate words must be valid English BIP39 words

    if invalid_words:
        raise ValueError(f"invalid candidate BIP39 words: {invalid_words}")

    return candidates


def read_candidate_words(
    bip39_words: list[str],
    bip39_words_set: set[str],
) -> list[str]:
    """
    Read candidate words and retry until they are valid.
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
        return default                             # Empty input uses the default value

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
        return default                             # Empty input uses the default value

    try:
        value = int(text)
    except ValueError:
        raise ValueError("please enter a valid integer")

    if value <= 0:
        raise ValueError("value must be greater than 0")

    return value


def read_yes_or_no(prompt: str) -> bool:
    """
    Read a yes/no answer and retry until valid.
    """

    while True:
        answer = input(prompt).strip().lower()     # Normalize yes/no answer

        if answer in ("y", "yes"):
            return True

        if answer in ("n", "no"):
            return False

        print("Please enter yes or no.")


def is_valid_mnemonic(mnemonic: str) -> bool:
    """
    Return True if the mnemonic is a valid English BIP39 mnemonic.
    """

    return Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic)  # Check BIP39 checksum


def build_receive_context(mnemonic: str, passphrase: str):
    """
    Build a BIP84 Bitcoin receiving-address derivation context.
    """

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)      # Generate seed from mnemonic and optional passphrase

    return (
        Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)                 # Create Bitcoin mainnet BIP84 context
        .Purpose()                                                     # Derivation level: m/84'
        .Coin()                                                        # Derivation level: m/84'/0'
        .Account(0)                                                    # Derivation level: m/84'/0'/0'
        .Change(Bip44Changes.CHAIN_EXT)                                # Derivation level: m/84'/0'/0'/0
    )


def format_duration(seconds: float) -> str:
    """
    Format duration into a readable string.
    """

    minute = 60                                  # Seconds in one minute
    hour = 60 * minute                           # Seconds in one hour
    day = 24 * hour                              # Seconds in one day
    year = 365 * day                             # Approximate seconds in one year

    if seconds < minute:
        return f"{seconds:.2f} seconds"

    if seconds < hour:
        return f"{seconds / minute:.2f} minutes"

    if seconds < day:
        return f"{seconds / hour:.2f} hours"

    if seconds < year:
        return f"{seconds / day:.2f} days"

    years = seconds / year                       # Convert very long duration to years

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
)                                                     # Read target address with retry

if not target_address.startswith("bc1q"):
    print()
    print("Warning: this script is designed for BIP84 bc1q addresses.")
    print("If your address starts with 1, 3, or bc1p, this script may not be suitable.")
    print()


words_list = Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH)   # Load English BIP39 word-list object

bip39_words = [
    words_list.GetWordAtIdx(index)
    for index in range(words_list.Length())
]                                                     # Convert BIP39 word-list object into a Python list

bip39_words_set = set(bip39_words)                    # Use set for fast word validation


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

mnemonic_words = read_mnemonic_template(bip39_words_set)       # Read mnemonic template with retry


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

candidates = read_candidate_words(bip39_words, bip39_words_set)  # Read candidate words with retry


print()

passphrase = getpass("BIP39 passphrase, or press Enter if none: ")  # Hidden input for optional BIP39 passphrase

start_index = read_until_valid(
    "Enter start address index, default 0: ",
    lambda text: parse_non_negative_int(text, default=0),
)                                                     # Read start address index with retry

address_count = read_until_valid(
    "Enter number of addresses to check, default 20: ",
    lambda text: parse_positive_int(text, default=20),
)                                                     # Read number of address indexes with retry


missing_positions = [
    index
    for index, word in enumerate(mnemonic_words)
    if word == "?"
]                                                     # Store zero-based positions of unknown words

total_combinations = len(candidates) ** len(missing_positions)  # Exact number of candidate combinations


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
        keep_window_open()


input("Press Enter to start the search, or Ctrl+C to stop now.")


start_time = time.time()                              # Search start time
checked_count = 0                                     # Total checked combinations
valid_mnemonic_count = 0                              # Total candidates that passed BIP39 checksum


for replacement_words in itertools.product(candidates, repeat=len(missing_positions)):
    checked_count += 1                                # Count one candidate combination

    test_words = mnemonic_words.copy()                # Copy template words before replacing ? positions

    for position, replacement_word in zip(missing_positions, replacement_words):
        test_words[position] = replacement_word        # Fill each unknown position with current candidate word

    mnemonic = " ".join(test_words)                   # Build full mnemonic text

    if not is_valid_mnemonic(mnemonic):
        if checked_count % PROGRESS_INTERVAL == 0:
            elapsed = max(time.time() - start_time, 0.000001)  # Avoid division by zero
            speed = checked_count / elapsed                    # Current average combinations per second
            remaining = total_combinations - checked_count      # Remaining combinations
            eta = remaining / speed                             # Estimated remaining time

            print(
                f"Checked {checked_count:,} / {total_combinations:,}, "
                f"valid {valid_mnemonic_count:,}, "
                f"speed {speed:,.2f}/sec, "
                f"ETA {format_duration(eta)}"
            )

        continue                                      # Invalid checksum, skip address derivation

    valid_mnemonic_count += 1                         # Count one valid BIP39 mnemonic candidate
    receive_ctx = build_receive_context(mnemonic, passphrase)  # Build BIP84 context only for valid mnemonic

    for address_index in range(start_index, start_index + address_count):
        address = receive_ctx.AddressIndex(address_index).PublicKey().ToAddress()  # Derive one receiving address

        if address == target_address:
            path = f"m/84'/0'/0'/0/{address_index}"   # Matching derivation path

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
        elapsed = max(time.time() - start_time, 0.000001)      # Elapsed search time
        speed = checked_count / elapsed                        # Current average speed
        remaining = total_combinations - checked_count          # Remaining combinations
        eta = remaining / speed                                 # Estimated remaining time

        print(
            f"Checked {checked_count:,} / {total_combinations:,}, "
            f"valid {valid_mnemonic_count:,}, "
            f"speed {speed:,.2f}/sec, "
            f"ETA {format_duration(eta)}"
        )


elapsed = max(time.time() - start_time, 0.000001)      # Total elapsed time

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

keep_window_open()
