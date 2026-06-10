"""
BIP39 Mnemonic Recovery Script

Purpose:
    This script attempts to recover a BIP39 mnemonic phrase when you know the
    target wallet address and suspect that 1 or 2 words in the mnemonic are wrong.

Supported coins:
    1. Bitcoin, configured with COIN_MODE = "BTC"
    2. Zcash transparent address, configured with COIN_MODE = "ZEC"

Bitcoin address types and derivation paths:
    1...     -> Legacy        -> BIP44 -> m/44'/0'/0'/0/0
    3...     -> Nested SegWit -> BIP49 -> m/49'/0'/0'/0/0
    bc1q...  -> Native SegWit -> BIP84 -> m/84'/0'/0'/0/0
    bc1p...  -> Taproot       -> BIP86 -> m/86'/0'/0'/0/0

Zcash address type and derivation path:
    t1...    -> Transparent address -> BIP44 -> m/44'/133'/0'/0/0

Search process:
    1. First, the script checks whether the current mnemonic is already correct.
    2. If not, it checks every position and tries replacing 1 word.
    3. If still not found, it checks every pair of positions and tries replacing 2 words.
    4. Every candidate mnemonic is checked with the BIP39 checksum first.
    5. Only candidates that pass the BIP39 checksum are used to derive an address.
    6. If the derived first address equals TARGET_ADDR, the mnemonic is considered found.

Important safety notes:
    1. Use this script only for recovering your own wallet.
    2. Never share your real mnemonic phrase with anyone.
    3. Do not run a real mnemonic on an online, shared, cloud, or untrusted machine.
    4. Prefer running this script on an offline computer.
    5. Make sure your computer is free from malware before entering a real mnemonic.
    6. If your wallet used a BIP39 passphrase, you must set PASSPHRASE correctly.
    7. This script checks only address index 0 by default.
    8. If the target address is not the first address, this script may not find it.
    9. Searching for 2 wrong words can take a long time because the search space is large.

Dependency:
    pip install bip-utils

You usually only need to edit these values:
    MNEMONIC_WORDS
    COIN_MODE
    TARGET_ADDR
    PASSPHRASE
"""

from itertools import combinations, product
from multiprocessing import Pool, cpu_count

from bip_utils import (
    Bip39Languages,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    Bip86,
    Bip86Coins,
    Bip44Changes,
)

from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter


# =========================
# Edit only this section
# =========================

MNEMONIC_WORDS = """

""".strip().lower().split()  # Converts the mnemonic to lowercase and splits it into words

COIN_MODE = "BTC"            # Use "BTC" for Bitcoin or "ZEC" for Zcash

TARGET_ADDR = ""             # Enter the target wallet address here

PASSPHRASE = ""              # Keep this empty if your wallet did not use a BIP39 passphrase


# =========================
# Fixed configuration
# =========================

LANGUAGE = Bip39Languages.ENGLISH                              # Use the English BIP39 wordlist

_words_obj = Bip39WordsListGetter().GetByLanguage(LANGUAGE)    # Load the built-in BIP39 wordlist

WORDLIST = []                                                   # Store all 2048 BIP39 English words
for i in range(_words_obj.Length()):
    WORDLIST.append(_words_obj.GetWordAtIdx(i))                 # Add each word to WORDLIST

WORDSET = set(WORDLIST)                                         # Use a set for faster word lookup

VALIDATOR = Bip39MnemonicValidator(LANGUAGE)                    # Create a BIP39 checksum validator


def make_mnemonic(replacements=None) -> str:
    """Build a mnemonic string from the original words and optional replacements."""

    words = MNEMONIC_WORDS.copy()                               # Copy the original words safely

    if replacements is None:
        return " ".join(words)                                  # Return the original mnemonic

    for pos, word in replacements:
        words[pos] = word                                       # Replace the selected word

    return " ".join(words)                                      # Convert the word list back to a string


def is_valid_bip39(mnemonic: str) -> bool:
    """Check whether a mnemonic passes the BIP39 checksum."""

    try:
        return VALIDATOR.IsValid(mnemonic)                      # True only if the checksum is valid
    except Exception:
        return False                                            # Treat validation errors as invalid


def derive_btc_legacy(seed) -> str:
    """Derive BTC Legacy address: m/44'/0'/0'/0/0."""

    return (
        Bip44.FromSeed(seed, Bip44Coins.BITCOIN)                # Use Bitcoin BIP44 configuration
        .Purpose()                                              # 44'
        .Coin()                                                 # 0'
        .Account(0)                                             # Account 0'
        .Change(Bip44Changes.CHAIN_EXT)                         # External receiving chain /0
        .AddressIndex(0)                                        # First address /0
        .PublicKey()                                            # Get the public key
        .ToAddress()                                            # Convert to Legacy address, usually starts with 1
    )


def derive_btc_nested_segwit(seed) -> str:
    """Derive BTC Nested SegWit address: m/49'/0'/0'/0/0."""

    return (
        Bip49.FromSeed(seed, Bip49Coins.BITCOIN)                # Use Bitcoin BIP49 configuration
        .Purpose()                                              # 49'
        .Coin()                                                 # 0'
        .Account(0)                                             # Account 0'
        .Change(Bip44Changes.CHAIN_EXT)                         # External receiving chain /0
        .AddressIndex(0)                                        # First address /0
        .PublicKey()                                            # Get the public key
        .ToAddress()                                            # Convert to Nested SegWit address, usually starts with 3
    )


def derive_btc_native_segwit(seed) -> str:
    """Derive BTC Native SegWit address: m/84'/0'/0'/0/0."""

    return (
        Bip84.FromSeed(seed, Bip84Coins.BITCOIN)                # Use Bitcoin BIP84 configuration
        .Purpose()                                              # 84'
        .Coin()                                                 # 0'
        .Account(0)                                             # Account 0'
        .Change(Bip44Changes.CHAIN_EXT)                         # External receiving chain /0
        .AddressIndex(0)                                        # First address /0
        .PublicKey()                                            # Get the public key
        .ToAddress()                                            # Convert to Native SegWit address, usually starts with bc1q
    )


def derive_btc_taproot(seed) -> str:
    """Derive BTC Taproot address: m/86'/0'/0'/0/0."""

    return (
        Bip86.FromSeed(seed, Bip86Coins.BITCOIN)                # Use Bitcoin BIP86 configuration
        .Purpose()                                              # 86'
        .Coin()                                                 # 0'
        .Account(0)                                             # Account 0'
        .Change(Bip44Changes.CHAIN_EXT)                         # External receiving chain /0
        .AddressIndex(0)                                        # First address /0
        .PublicKey()                                            # Get the public key
        .ToAddress()                                            # Convert to Taproot address, usually starts with bc1p
    )


def derive_first_btc_address(mnemonic: str) -> str:
    """Derive the first Bitcoin address based on the TARGET_ADDR prefix."""

    seed = Bip39SeedGenerator(mnemonic).Generate(PASSPHRASE)    # Generate seed from mnemonic and passphrase
    target = TARGET_ADDR.lower()                                # Normalize the target address for prefix checks

    if target.startswith("1"):
        return derive_btc_legacy(seed)                          # 1... means BIP44 Legacy

    if target.startswith("3"):
        return derive_btc_nested_segwit(seed)                    # 3... means BIP49 Nested SegWit

    if target.startswith("bc1q"):
        return derive_btc_native_segwit(seed)                    # bc1q... means BIP84 Native SegWit

    if target.startswith("bc1p"):
        return derive_btc_taproot(seed)                          # bc1p... means BIP86 Taproot

    raise ValueError("Unsupported Bitcoin address type")          # Stop if the address prefix is not recognized


def derive_first_zcash_address(mnemonic: str) -> str:
    """Derive the first Zcash transparent address: m/44'/133'/0'/0/0."""

    seed = Bip39SeedGenerator(mnemonic).Generate(PASSPHRASE)     # Generate seed from mnemonic and passphrase

    return (
        Bip44.FromSeed(seed, Bip44Coins.ZCASH)                   # Use Zcash BIP44 configuration
        .Purpose()                                               # 44'
        .Coin()                                                  # 133'
        .Account(0)                                              # Account 0'
        .Change(Bip44Changes.CHAIN_EXT)                          # External receiving chain /0
        .AddressIndex(0)                                         # First address /0
        .PublicKey()                                             # Get the public key
        .ToAddress()                                             # Convert to Zcash transparent address
    )


def derive_first_address(mnemonic: str) -> str:
    """Derive the first address for the selected coin."""

    mode = COIN_MODE.upper()                                     # Normalize the coin mode

    if mode == "BTC":
        return derive_first_btc_address(mnemonic)                # Derive a Bitcoin address

    if mode == "ZEC":
        return derive_first_zcash_address(mnemonic)              # Derive a Zcash address

    raise ValueError(f"Unsupported COIN_MODE: {COIN_MODE}")       # Reject unsupported coin modes


def get_derivation_info() -> str:
    """Return a readable description of the derivation path being used."""

    mode = COIN_MODE.upper()                                     # Normalize the coin mode
    target = TARGET_ADDR.lower()                                 # Normalize the target address for prefix checks

    if mode == "ZEC":
        return "ZEC: m/44'/133'/0'/0/0"                          # Zcash transparent address path

    if mode != "BTC":
        return "Unknown coin mode"                               # Fallback for unsupported modes

    if target.startswith("1"):
        return "BTC Legacy: m/44'/0'/0'/0/0"                     # Legacy path

    if target.startswith("3"):
        return "BTC Nested SegWit: m/49'/0'/0'/0/0"              # Nested SegWit path

    if target.startswith("bc1q"):
        return "BTC Native SegWit: m/84'/0'/0'/0/0"              # Native SegWit path

    if target.startswith("bc1p"):
        return "BTC Taproot: m/86'/0'/0'/0/0"                    # Taproot path

    return "BTC: unable to detect path from address prefix"       # Unknown Bitcoin address type


def normalize_target_addr_for_compare() -> str:
    """Normalize TARGET_ADDR only when address comparison should be case-insensitive."""

    target = TARGET_ADDR.strip()                                 # Remove accidental leading or trailing spaces
    lower_target = target.lower()                                # Lowercase version for Bech32 addresses

    if lower_target.startswith("bc1"):
        return lower_target                                      # Bitcoin Bech32 addresses should be compared lowercase

    return target                                                # Base58 addresses are case-sensitive


def normalize_derived_addr_for_compare(address: str) -> str:
    """Normalize a derived address only when comparison should be case-insensitive."""

    lower_address = address.lower()                              # Lowercase version for Bech32 addresses

    if lower_address.startswith("bc1"):
        return lower_address                                     # Bitcoin Bech32 addresses should be compared lowercase

    return address                                               # Base58 addresses are case-sensitive


def address_matches(mnemonic: str) -> bool:
    """Check whether a candidate mnemonic derives the target address."""

    if not is_valid_bip39(mnemonic):
        return False                                             # Skip candidates that fail the BIP39 checksum

    try:
        address = derive_first_address(mnemonic)                 # Derive the first address for the selected coin
    except Exception:
        return False                                             # Treat derivation errors as non-matching candidates

    normalized_address = normalize_derived_addr_for_compare(address)  # Normalize derived address if needed
    normalized_target = normalize_target_addr_for_compare()           # Normalize target address if needed

    return normalized_address == normalized_target                # Match found only when addresses are equal


def make_result(replacements):
    """Build a consistent result object when a matching mnemonic is found."""

    positions = []                                               # Store corrected positions, using 1-based numbering
    words = []                                                   # Store replacement words

    for pos, word in replacements:
        positions.append(pos + 1)                                # Convert internal 0-based index to user-facing 1-based index
        words.append(word)                                       # Store the replacement word

    return {
        "error_count": len(replacements),                        # Number of corrected words
        "mnemonic": make_mnemonic(replacements),                 # Full recovered mnemonic
        "positions": positions,                                  # Corrected word positions
        "words": words,                                          # Correct replacement words
    }


def check_original_mnemonic():
    """Check whether the current mnemonic is already correct."""

    mnemonic = make_mnemonic()                                   # Build the original mnemonic string

    if address_matches(mnemonic):
        return make_result([])                                   # No replacement is needed

    return None                                                  # Original mnemonic does not match


def has_unchanged_word(new_words, original_words) -> bool:
    """Return True if any candidate replacement word is unchanged."""

    for i in range(len(new_words)):
        if new_words[i] == original_words[i]:
            return True                                          # Skip because this is not a true replacement

    return False                                                 # Every selected word is changed


def build_replacements(positions, new_words):
    """Build replacement pairs from positions and candidate words."""

    replacements = []                                            # Replacement format: [(position, new_word), ...]

    for i in range(len(positions)):
        replacements.append((positions[i], new_words[i]))         # Pair each position with its candidate word

    return replacements                                          # Return all replacement pairs


def check_positions(positions):
    """Check whether the given one or two positions contain wrong words."""

    original_words = []                                          # Store the original words at the selected positions

    for pos in positions:
        original_words.append(MNEMONIC_WORDS[pos])               # Read the original word at this position

    for new_words in product(WORDLIST, repeat=len(positions)):    # Try every possible word combination
        if has_unchanged_word(new_words, original_words):
            continue                                             # Skip candidates where a selected word did not change

        replacements = build_replacements(positions, new_words)   # Build replacement instructions
        mnemonic = make_mnemonic(replacements)                   # Build candidate mnemonic

        if address_matches(mnemonic):
            return make_result(replacements)                     # Return immediately when a match is found

    return None                                                  # No match found for these positions


def validate_word_count():
    """Validate that the mnemonic length is allowed by BIP39."""

    word_count = len(MNEMONIC_WORDS)                             # BIP39 allows only specific word counts

    if word_count in (12, 15, 18, 21, 24):
        return                                                   # Word count is valid

    raise ValueError(
        f"Mnemonic word count is {word_count}; BIP39 allows only 12, 15, 18, 21, or 24 words"
    )


def validate_coin_mode():
    """Validate the selected coin mode."""

    mode = COIN_MODE.upper()                                     # Normalize the coin mode

    if mode in ("BTC", "ZEC"):
        return                                                   # Supported coin mode

    raise ValueError("COIN_MODE must be either 'BTC' or 'ZEC'")   # Unsupported coin mode


def validate_target_addr():
    """Validate that the target address is not empty."""

    if TARGET_ADDR:
        return                                                   # Target address is present

    raise ValueError("Please set TARGET_ADDR before running the script")


def warn_btc_addr():
    """Warn if the Bitcoin target address does not look like a common mainnet address."""

    target = TARGET_ADDR.lower()                                 # Normalize for prefix checks

    if target.startswith("1"):
        return                                                   # Legacy mainnet address

    if target.startswith("3"):
        return                                                   # Nested SegWit mainnet address

    if target.startswith("bc1q"):
        return                                                   # Native SegWit mainnet address

    if target.startswith("bc1p"):
        return                                                   # Taproot mainnet address

    print("Warning: TARGET_ADDR does not look like a common Bitcoin mainnet address.")


def warn_zec_addr():
    """Warn if the Zcash target address does not look like a transparent address."""

    if TARGET_ADDR.startswith("t1"):
        return                                                   # Common Zcash transparent address prefix

    print("Warning: TARGET_ADDR does not start with t1. Please confirm it is a Zcash transparent address.")


def warn_unknown_words():
    """Warn if any mnemonic word is not in the English BIP39 wordlist."""

    unknown_words = []                                           # Store unknown words and their positions

    for idx, word in enumerate(MNEMONIC_WORDS):
        if word in WORDSET:
            continue                                             # Known BIP39 word

        unknown_words.append((idx + 1, word))                    # Store 1-based position and unknown word

    if not unknown_words:
        return                                                   # All words are known BIP39 words

    print("\nWarning: these words are not in the English BIP39 wordlist:")

    for pos, word in unknown_words:
        print(f"Word {pos}: {word}")                              # Print the unknown word and its position

    print("The search will continue because these positions may be the wrong words.")


def validate_input():
    """Run all input validation checks."""

    validate_word_count()                                        # Check mnemonic length
    validate_coin_mode()                                         # Check selected coin mode
    validate_target_addr()                                       # Check target address presence

    mode = COIN_MODE.upper()                                     # Normalize the coin mode

    if mode == "BTC":
        warn_btc_addr()                                          # Check Bitcoin address prefix

    if mode == "ZEC":
        warn_zec_addr()                                          # Check Zcash address prefix

    warn_unknown_words()                                         # Check all words against the BIP39 wordlist


def print_result(result):
    """Print the recovered mnemonic result."""

    print("\n========== FOUND ==========")
    print(f"Wrong word count: {result['error_count']}")

    for pos, word in zip(result["positions"], result["words"]):
        print(f"Replace word {pos} with: {word}")                 # Print each corrected word

    print("\nRecovered mnemonic:")
    print(result["mnemonic"])                                    # Print the full recovered mnemonic
    print("===========================")


def build_one_error_jobs():
    """Build search jobs for the 1-wrong-word case."""

    jobs = []                                                    # Each job contains one position

    for pos in range(len(MNEMONIC_WORDS)):
        jobs.append((pos,))                                      # Single-item tuple, for example (3,)

    return jobs                                                  # Return all 1-position jobs


def build_two_error_jobs():
    """Build search jobs for the 2-wrong-word case."""

    jobs = []                                                    # Each job contains two positions

    for pair in combinations(range(len(MNEMONIC_WORDS)), 2):
        jobs.append(pair)                                        # Example: (0, 3), (1, 9)

    return jobs                                                  # Return all 2-position jobs


def build_jobs(error_count):
    """Build search jobs for a given wrong-word count."""

    if error_count == 1:
        return build_one_error_jobs()                            # Build jobs for 1 wrong word

    if error_count == 2:
        return build_two_error_jobs()                            # Build jobs for 2 wrong words

    raise ValueError("error_count must be either 1 or 2")          # This script supports only 1 or 2 wrong words


def search_errors(error_count):
    """Search for a matching mnemonic with the given number of wrong words."""

    jobs = build_jobs(error_count)                               # Build all position combinations
    theoretical_count = len(jobs) * (len(WORDLIST) ** error_count)  # Rough upper bound of candidates

    print(f"\nStarting search: {error_count} wrong word(s)")
    print(f"Position combinations to check: {len(jobs)}")
    print(f"Theoretical candidate count: {theoretical_count:,}")
    print(f"CPU process count: {cpu_count()}")

    with Pool(cpu_count()) as pool:                              # Use all available CPU cores
        for result in pool.imap_unordered(check_positions, jobs, chunksize=1):
            if result is not None:
                pool.terminate()                                 # Stop other workers after a match is found
                return result                                    # Return the found result immediately

    return None                                                  # No match found


def print_search_params():
    """Print the current search configuration."""

    print("========== Search Parameters ==========")
    print(f"Coin mode: {COIN_MODE.upper()}")
    print(f"Mnemonic word count: {len(MNEMONIC_WORDS)}")
    print(f"Target address: {TARGET_ADDR}")
    print(f"Derivation path: {get_derivation_info()}")
    print("=======================================")


def print_not_found():
    """Print possible reasons when no matching mnemonic is found."""

    print("\nNo matching result found.")
    print("Possible reasons:")
    print("1. More than 2 words are wrong.")
    print("2. The target address was not generated from this mnemonic.")
    print("3. A BIP39 passphrase was used but PASSPHRASE is incorrect or empty.")
    print("4. The Bitcoin address type or derivation path does not match.")
    print("5. The Zcash address is not a t1 transparent address.")
    print("6. The target address is not the first address, meaning it is not address index 0.")


def main():
    """Main program entry point."""

    validate_input()                                             # Validate all user-provided settings
    print_search_params()                                        # Print configuration for confirmation

    print("\nChecking whether the current mnemonic is already correct")

    result = check_original_mnemonic()                           # Check the original mnemonic first

    if result is not None:
        print_result(result)                                     # Print result if no correction is needed
        return                                                   # Exit program

    result = search_errors(1)                                    # Search for 1 wrong word

    if result is not None:
        print_result(result)                                     # Print result if found
        return                                                   # Exit program

    result = search_errors(2)                                    # Search for 2 wrong words

    if result is not None:
        print_result(result)                                     # Print result if found
        return                                                   # Exit program

    print_not_found()                                            # Print failure explanation


if __name__ == "__main__":
    main()                                                       # Run main only when this file is executed directly
