"""
BIP39 Order Recovery

File name suggestion:
    bip39_order_recovery.py

Purpose:
    This script tries to recover the correct order of a BIP39 mnemonic phrase.
    It is designed for the case where all mnemonic words are known, every word is
    spelled correctly, and no word is missing or extra, but the order may be wrong.

Supported coins:
    BTC  -> Bitcoin
    ETH  -> Ethereum
    ZEC  -> Zcash transparent address
    SOL  -> Solana

What this script does:
    It asks the user for the coin, target address, optional BIP39 passphrase,
    unordered mnemonic words, and optional fixed word positions.
    It strictly validates all input before searching.
    If any input is invalid, it prints precise errors and does not search.
    If all input is valid, it tries different word orders and checks whether the
    derived address matches the target address.

What this script does not do:
    It does not fix misspelled words.
    It does not remove invalid words.
    It does not guess missing words.
    It does not replace wrong words.
    It does not search different address indexes.
    It only checks address index 0.

Derivation paths:
    BTC Legacy        -> 1...    -> m/44'/0'/0'/0/0
    BTC Nested SegWit -> 3...    -> m/49'/0'/0'/0/0
    BTC Native SegWit -> bc1q... -> m/84'/0'/0'/0/0
    BTC Taproot       -> bc1p... -> m/86'/0'/0'/0/0
    ETH               -> 0x...   -> m/44'/60'/0'/0/0
    ZEC               -> t1...   -> m/44'/133'/0'/0/0
    SOL               -> Base58  -> m/44'/501'/0'

Performance warning:
    Full order recovery can be extremely slow.
    12 words means up to 479,001,600 possible orders.
    18 or 24 words are usually not practical unless many positions are fixed.

Optional fixed positions:
    If some word positions are already known, enter them like this:
        1:abandon, 5:legal, 12:zoo
    Position numbers are 1-based, not 0-based.

Safety notes:
    Use this script only for recovering your own wallet.
    Never send your mnemonic phrase to anyone.
    Prefer running this script offline.
    Do not run a real mnemonic on a cloud server or shared machine.
    Make sure your computer is clean before entering a real mnemonic.

Dependency:
    pip install bip-utils
"""

from collections import Counter
from difflib import get_close_matches
from itertools import permutations
from math import factorial
from multiprocessing import Pool, cpu_count
from bip_utils import (
    Bip39Languages,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    Bip86,
    Bip86Coins,
)
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter

SCRIPT_NAME = "BIP39 Order Recovery"            # Human-readable script name
SCRIPT_VERSION = "1.0.0"                         # Version number for easier tracking
MNEMONIC_WORDS = []                              # Filled after user input
COIN_MODE = ""                                   # BTC, ETH, ZEC, or SOL
TARGET_ADDR = ""                                 # Target address to match
PASSPHRASE = ""                                  # Optional BIP39 passphrase
KNOWN_POSITIONS = {}                             # Optional fixed positions, 1-based from user input
PERMUTATION_CHUNK_SIZE = 1000                    # Number of candidate orders per worker task
PROGRESS_EVERY_CHUNKS = 1000                     # Print progress every N completed chunks
LANGUAGE = Bip39Languages.ENGLISH                # This script uses only English BIP39 words
_words_obj = Bip39WordsListGetter().GetByLanguage(LANGUAGE)  # Load built-in BIP39 English wordlist
WORDLIST = []                                    # Full BIP39 wordlist as a normal list
for i in range(_words_obj.Length()):
    WORDLIST.append(_words_obj.GetWordAtIdx(i))  # Avoid list comprehension by request
WORDSET = set(WORDLIST)                          # Fast lookup for BIP39 word validation
VALIDATOR = Bip39MnemonicValidator(LANGUAGE)     # BIP39 checksum validator
BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # Used by SOL
HEX_CHARS = "0123456789abcdefABCDEF"             # Used by ETH address validation

def print_header():
    """Print script title."""
    print(f"{SCRIPT_NAME} v{SCRIPT_VERSION}")    # Show name and version at startup
    print("Recover a BIP39 mnemonic when all words are known but the order may be wrong.")
    print("")

def ask_user_inputs():
    """Ask the user for all required runtime values."""
    global COIN_MODE, TARGET_ADDR, PASSPHRASE, MNEMONIC_WORDS, KNOWN_POSITIONS
    print("Supported coins: BTC, ETH, ZEC, SOL")
    COIN_MODE = input("Enter coin symbol: ").strip().upper()       # Normalize coin symbol
    TARGET_ADDR = input("Enter target address: ").strip()          # Keep address text exactly, except spaces
    PASSPHRASE = input("Enter BIP39 passphrase, or leave empty: ") # Do not strip passphrase; spaces may matter
    print("")
    print("Enter the mnemonic words you know.")
    print("The order may be wrong, but every word must be present and spelled correctly.")
    mnemonic_text = input("Mnemonic words: ").strip().lower()      # BIP39 English words are lowercase
    MNEMONIC_WORDS = mnemonic_text.split()                         # Split by whitespace
    print("")
    print("Optional fixed positions, example: 1:abandon, 5:legal, 12:zoo")
    fixed_text = input("Known fixed positions, or leave empty: ").strip().lower()
    KNOWN_POSITIONS = parse_known_positions(fixed_text)            # Convert fixed-position text to a dict

def parse_known_positions(text):
    """Parse optional fixed-position input into a dictionary."""
    fixed = {}                                                     # Stores position -> word
    if not text:
        return fixed                                               # Empty input means no fixed positions
    parts = text.split(",")                                        # Separate items by comma
    for raw_part in parts:
        part = raw_part.strip()                                    # Remove surrounding spaces
        if not part:
            continue                                               # Ignore empty comma parts
        if ":" not in part:
            fixed[part] = None                                     # Store invalid key so validation can report it
            continue
        pair = part.split(":", 1)                                  # Split only once to avoid accidental extra colons
        pos_text = pair[0].strip()                                 # Left side should be a number
        word = pair[1].strip().lower()                             # Right side should be a BIP39 word
        if not pos_text.isdigit():
            fixed[pos_text] = word                                 # Store invalid key for precise error reporting
            continue
        pos = int(pos_text)                                        # Convert 1-based text position to integer
        fixed[pos] = word                                          # Store the fixed word
    return fixed

def wait_before_exit():
    """Keep the console window open after the script finishes."""
    print("")
    try:
        input("Press Enter to exit...")                            # Prevents double-click window from closing
    except EOFError:
        return                                                     # Safe fallback when input is unavailable

def make_mnemonic(words) -> str:
    """Build a mnemonic string from a word sequence."""
    return " ".join(words)                                         # BIP39 mnemonic words are space-separated

def is_valid_bip39(mnemonic: str) -> bool:
    """Check whether a mnemonic passes the BIP39 checksum."""
    try:
        return VALIDATOR.IsValid(mnemonic)                         # Checksum filter removes most wrong orders
    except Exception:
        return False                                               # Validation errors are treated as invalid candidates

def derive_btc_legacy(seed) -> str:
    """Derive BTC Legacy address: m/44'/0'/0'/0/0."""
    return (
        Bip44.FromSeed(seed, Bip44Coins.BITCOIN)                   # Select Bitcoin BIP44
        .Purpose()                                                 # 44'
        .Coin()                                                    # 0'
        .Account(0)                                                # account 0'
        .Change(Bip44Changes.CHAIN_EXT)                            # external receiving chain /0
        .AddressIndex(0)                                           # first address /0
        .PublicKey()                                               # public key
        .ToAddress()                                               # Legacy address, usually starts with 1
    )

def derive_btc_nested_segwit(seed) -> str:
    """Derive BTC Nested SegWit address: m/49'/0'/0'/0/0."""
    return (
        Bip49.FromSeed(seed, Bip49Coins.BITCOIN)                   # Select Bitcoin BIP49
        .Purpose()                                                 # 49'
        .Coin()                                                    # 0'
        .Account(0)                                                # account 0'
        .Change(Bip44Changes.CHAIN_EXT)                            # external receiving chain /0
        .AddressIndex(0)                                           # first address /0
        .PublicKey()                                               # public key
        .ToAddress()                                               # Nested SegWit address, usually starts with 3
    )

def derive_btc_native_segwit(seed) -> str:
    """Derive BTC Native SegWit address: m/84'/0'/0'/0/0."""
    return (
        Bip84.FromSeed(seed, Bip84Coins.BITCOIN)                   # Select Bitcoin BIP84
        .Purpose()                                                 # 84'
        .Coin()                                                    # 0'
        .Account(0)                                                # account 0'
        .Change(Bip44Changes.CHAIN_EXT)                            # external receiving chain /0
        .AddressIndex(0)                                           # first address /0
        .PublicKey()                                               # public key
        .ToAddress()                                               # Native SegWit address, usually starts with bc1q
    )

def derive_btc_taproot(seed) -> str:
    """Derive BTC Taproot address: m/86'/0'/0'/0/0."""
    return (
        Bip86.FromSeed(seed, Bip86Coins.BITCOIN)                   # Select Bitcoin BIP86
        .Purpose()                                                 # 86'
        .Coin()                                                    # 0'
        .Account(0)                                                # account 0'
        .Change(Bip44Changes.CHAIN_EXT)                            # external receiving chain /0
        .AddressIndex(0)                                           # first address /0
        .PublicKey()                                               # public key
        .ToAddress()                                               # Taproot address, usually starts with bc1p
    )

def derive_first_btc_address(mnemonic: str) -> str:
    """Derive the first Bitcoin address based on the target address prefix."""
    seed = Bip39SeedGenerator(mnemonic).Generate(PASSPHRASE)       # Convert mnemonic to seed
    target = TARGET_ADDR.lower()                                   # Prefix checks are easier in lowercase
    if target.startswith("1"):
        return derive_btc_legacy(seed)                             # 1... means Legacy
    if target.startswith("3"):
        return derive_btc_nested_segwit(seed)                       # 3... means Nested SegWit
    if target.startswith("bc1q"):
        return derive_btc_native_segwit(seed)                       # bc1q... means Native SegWit
    if target.startswith("bc1p"):
        return derive_btc_taproot(seed)                             # bc1p... means Taproot
    raise ValueError("Unsupported Bitcoin address type")             # Should be caught during validation

def derive_first_eth_address(mnemonic: str) -> str:
    """Derive the first Ethereum address: m/44'/60'/0'/0/0."""
    seed = Bip39SeedGenerator(mnemonic).Generate(PASSPHRASE)       # Convert mnemonic to seed
    return (
        Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)                  # Select Ethereum BIP44
        .Purpose()                                                 # 44'
        .Coin()                                                    # 60'
        .Account(0)                                                # account 0'
        .Change(Bip44Changes.CHAIN_EXT)                            # external chain /0
        .AddressIndex(0)                                           # first address /0
        .PublicKey()                                               # public key
        .ToAddress()                                               # Ethereum address
    )

def derive_first_zcash_address(mnemonic: str) -> str:
    """Derive the first Zcash transparent address: m/44'/133'/0'/0/0."""
    seed = Bip39SeedGenerator(mnemonic).Generate(PASSPHRASE)       # Convert mnemonic to seed
    return (
        Bip44.FromSeed(seed, Bip44Coins.ZCASH)                     # Select Zcash BIP44
        .Purpose()                                                 # 44'
        .Coin()                                                    # 133'
        .Account(0)                                                # account 0'
        .Change(Bip44Changes.CHAIN_EXT)                            # external chain /0
        .AddressIndex(0)                                           # first address /0
        .PublicKey()                                               # public key
        .ToAddress()                                               # Zcash transparent address
    )

def derive_first_solana_address(mnemonic: str) -> str:
    """Derive the default Solana address: m/44'/501'/0'."""
    seed = Bip39SeedGenerator(mnemonic).Generate(PASSPHRASE)       # Convert mnemonic to seed
    return (
        Bip44.FromSeed(seed, Bip44Coins.SOLANA)                    # Select Solana BIP44 configuration
        .DeriveDefaultPath()                                       # Default Solana path in bip_utils
        .PublicKey()                                               # public key
        .ToAddress()                                               # Solana address
    )

def derive_first_address(mnemonic: str) -> str:
    """Derive the first address for the selected coin."""
    if COIN_MODE == "BTC":
        return derive_first_btc_address(mnemonic)                  # Bitcoin
    if COIN_MODE == "ETH":
        return derive_first_eth_address(mnemonic)                  # Ethereum
    if COIN_MODE == "ZEC":
        return derive_first_zcash_address(mnemonic)                # Zcash
    if COIN_MODE == "SOL":
        return derive_first_solana_address(mnemonic)               # Solana
    raise ValueError("Unsupported coin mode")                       # Should be caught during validation

def normalize_target_addr_for_compare() -> str:
    """Normalize target address for comparison when needed."""
    target = TARGET_ADDR.strip()                                    # Remove accidental spaces
    if COIN_MODE == "ETH":
        return target.lower()                                       # ETH comparison ignores checksum casing here
    if COIN_MODE == "BTC":
        lower_target = target.lower()
        if lower_target.startswith("bc1"):
            return lower_target                                    # BTC Bech32 addresses compare lowercase
    return target                                                   # Base58 addresses are case-sensitive

def normalize_derived_addr_for_compare(address: str) -> str:
    """Normalize derived address for comparison when needed."""
    if COIN_MODE == "ETH":
        return address.lower()                                      # ETH comparison ignores checksum casing here
    if COIN_MODE == "BTC":
        lower_address = address.lower()
        if lower_address.startswith("bc1"):
            return lower_address                                   # BTC Bech32 addresses compare lowercase
    return address                                                  # Base58 addresses are case-sensitive

def address_matches_valid_mnemonic(mnemonic: str) -> bool:
    """Check whether a valid mnemonic derives the target address."""
    try:
        address = derive_first_address(mnemonic)                    # Derive address only after checksum passes
    except Exception:
        return False                                                # Candidate cannot match if derivation fails
    normalized_address = normalize_derived_addr_for_compare(address)
    normalized_target = normalize_target_addr_for_compare()
    return normalized_address == normalized_target                  # Final address comparison

def address_matches(mnemonic: str) -> bool:
    """Check whether a candidate mnemonic is valid and derives the target address."""
    if not is_valid_bip39(mnemonic):
        return False                                                # Invalid checksum means wrong order
    return address_matches_valid_mnemonic(mnemonic)                 # Only valid BIP39 candidates reach address derivation

def get_supported_coin_text() -> str:
    """Return supported coin symbols as text."""
    return "BTC, ETH, ZEC, SOL"

def add_coin_mode_errors(errors):
    """Add coin-mode validation errors."""
    if COIN_MODE == "BTC":
        return
    if COIN_MODE == "ETH":
        return
    if COIN_MODE == "ZEC":
        return
    if COIN_MODE == "SOL":
        return
    if not COIN_MODE:
        errors.append("Coin error: no coin symbol was entered.")
        return
    errors.append("Coin error: unsupported coin symbol '" + COIN_MODE + "'. Supported symbols are: " + get_supported_coin_text() + ".")

def add_target_empty_errors(errors):
    """Add target-address empty validation errors."""
    if TARGET_ADDR:
        return
    errors.append("Address error: target address is empty.")

def add_target_format_errors(errors):
    """Add target-address format validation errors."""
    if not TARGET_ADDR:
        return
    if COIN_MODE == "BTC":
        add_btc_address_errors(errors)
        return
    if COIN_MODE == "ETH":
        add_eth_address_errors(errors)
        return
    if COIN_MODE == "ZEC":
        add_zec_address_errors(errors)
        return
    if COIN_MODE == "SOL":
        add_sol_address_errors(errors)
        return

def add_btc_address_errors(errors):
    """Add Bitcoin address format errors."""
    target = TARGET_ADDR.strip()
    lower_target = target.lower()
    if lower_target.startswith("1"):
        return
    if lower_target.startswith("3"):
        return
    if lower_target.startswith("bc1q"):
        return
    if lower_target.startswith("bc1p"):
        return
    errors.append("Address error: selected coin is BTC, but the address does not look like a supported Bitcoin mainnet address. Expected prefix: 1, 3, bc1q, or bc1p. Entered address: " + target)

def add_eth_address_errors(errors):
    """Add Ethereum address format errors."""
    target = TARGET_ADDR.strip()
    if not target.startswith("0x") and not target.startswith("0X"):
        errors.append("Address error: selected coin is ETH, but the address does not start with 0x.")
    if len(target) != 42:
        errors.append("Address error: selected coin is ETH, but the address length is " + str(len(target)) + ". A common Ethereum address should be 42 characters including 0x.")
        return
    body = target[2:]
    for index, char in enumerate(body):
        if char in HEX_CHARS:
            continue
        errors.append("Address error: selected coin is ETH, but character " + str(index + 3) + " is not hexadecimal: " + char)
        return

def add_zec_address_errors(errors):
    """Add Zcash transparent address format errors."""
    target = TARGET_ADDR.strip()
    if target.startswith("t1"):
        return
    errors.append("Address error: selected coin is ZEC, but this script supports only Zcash transparent addresses starting with t1. Entered address: " + target)

def add_sol_address_errors(errors):
    """Add Solana address format errors."""
    target = TARGET_ADDR.strip()
    if len(target) < 32:
        errors.append("Address error: selected coin is SOL, but the address is too short. Entered length: " + str(len(target)) + ".")
        return
    if len(target) > 44:
        errors.append("Address error: selected coin is SOL, but the address is too long. Entered length: " + str(len(target)) + ".")
        return
    for index, char in enumerate(target):
        if char in BASE58_CHARS:
            continue
        errors.append("Address error: selected coin is SOL, but character " + str(index + 1) + " is not a valid Base58 character: " + char)
        return

def add_word_count_errors(errors):
    """Add mnemonic word-count validation errors."""
    word_count = len(MNEMONIC_WORDS)
    if word_count == 12:
        return
    if word_count == 15:
        return
    if word_count == 18:
        return
    if word_count == 21:
        return
    if word_count == 24:
        return
    if word_count == 0:
        errors.append("Mnemonic error: no mnemonic words were entered.")
        return
    errors.append("Mnemonic error: invalid word count. You entered " + str(word_count) + " words. BIP39 allows only 12, 15, 18, 21, or 24 words.")

def add_invalid_word_errors(errors):
    """Add precise errors for words not in the English BIP39 wordlist."""
    for index, word in enumerate(MNEMONIC_WORDS):
        if word in WORDSET:
            continue
        message = "Mnemonic word error: word " + str(index + 1) + " is not in the English BIP39 wordlist: " + word
        suggestions = get_close_matches(word, WORDLIST, n=3, cutoff=0.75)  # Give spelling hints for typos
        if suggestions:
            message = message + ". Possible intended word(s): " + ", ".join(suggestions)
        errors.append(message)

def add_known_position_parse_errors(errors):
    """Add precise errors for invalid fixed-position keys."""
    word_count = len(MNEMONIC_WORDS)
    for pos in KNOWN_POSITIONS:
        if isinstance(pos, int):
            continue
        errors.append("Fixed-position error: invalid position key '" + str(pos) + "'. Use format like 1:abandon, 5:legal.")
    for pos in KNOWN_POSITIONS:
        if not isinstance(pos, int):
            continue
        if pos < 1:
            errors.append("Fixed-position error: position " + str(pos) + " is invalid. Positions must start from 1.")
            continue
        if word_count == 0:
            continue
        if pos > word_count:
            errors.append("Fixed-position error: position " + str(pos) + " is outside the mnemonic length. The mnemonic has " + str(word_count) + " words.")

def add_known_position_word_errors(errors):
    """Add precise errors for invalid or unavailable fixed-position words."""
    counts = Counter(MNEMONIC_WORDS)                              # Count entered words so duplicates are handled correctly
    for pos in KNOWN_POSITIONS:
        if not isinstance(pos, int):
            continue
        word = KNOWN_POSITIONS[pos]
        if word is None:
            errors.append("Fixed-position error: position " + str(pos) + " has no word. Use format like " + str(pos) + ":word.")
            continue
        if not word:
            errors.append("Fixed-position error: position " + str(pos) + " has an empty word.")
            continue
        if word not in WORDSET:
            errors.append("Fixed-position error: word at position " + str(pos) + " is not in the English BIP39 wordlist: " + word)
            continue
        if counts[word] <= 0:
            errors.append("Fixed-position error: word at position " + str(pos) + " was not found in the entered mnemonic words: " + word)
            continue
        counts[word] = counts[word] - 1                            # Reserve one occurrence for this fixed position

def collect_input_errors():
    """Collect all detected input errors before search starts."""
    errors = []
    add_coin_mode_errors(errors)
    add_target_empty_errors(errors)
    add_target_format_errors(errors)
    add_word_count_errors(errors)
    add_invalid_word_errors(errors)
    add_known_position_parse_errors(errors)
    add_known_position_word_errors(errors)
    return errors

def print_input_errors(errors):
    """Print all detected input errors clearly."""
    print("")
    print("========== INPUT ERRORS ==========")
    number = 1
    for error in errors:
        print(str(number) + ". " + error)
        number = number + 1
    print("")
    print("Search was not started because the input above must be corrected first.")
    print("==================================")

def get_derivation_info() -> str:
    """Return a readable derivation path description."""
    target = TARGET_ADDR.lower()
    if COIN_MODE == "ETH":
        return "ETH: m/44'/60'/0'/0/0"
    if COIN_MODE == "ZEC":
        return "ZEC: m/44'/133'/0'/0/0"
    if COIN_MODE == "SOL":
        return "SOL: m/44'/501'/0'"
    if COIN_MODE != "BTC":
        return "Unknown"
    if target.startswith("1"):
        return "BTC Legacy: m/44'/0'/0'/0/0"
    if target.startswith("3"):
        return "BTC Nested SegWit: m/49'/0'/0'/0/0"
    if target.startswith("bc1q"):
        return "BTC Native SegWit: m/84'/0'/0'/0/0"
    if target.startswith("bc1p"):
        return "BTC Taproot: m/86'/0'/0'/0/0"
    return "BTC: unable to detect derivation path from address prefix"

def build_fixed_positions_zero_based():
    """Convert known fixed positions from 1-based to 0-based indexing."""
    fixed = {}
    for pos_one_based in KNOWN_POSITIONS:
        if not isinstance(pos_one_based, int):
            continue
        pos_zero_based = pos_one_based - 1                         # Convert user position to Python index
        word = KNOWN_POSITIONS[pos_one_based].lower()              # Normalize fixed word
        fixed[pos_zero_based] = word                               # Store zero-based fixed position
    return fixed

def build_free_words(fixed):
    """Build the list of words that still need permutation."""
    counts = Counter(MNEMONIC_WORDS)                               # Count all words, including duplicates
    for pos in fixed:
        word = fixed[pos]
        counts[word] = counts[word] - 1                            # Remove words already locked in fixed positions
    free_words = []
    for word in counts:
        amount = counts[word]
        for _ in range(amount):
            free_words.append(word)                                # Add remaining free words one by one
    return free_words

def build_candidate_words(free_order, fixed):
    """Merge free words with fixed positions into a complete candidate order."""
    candidate = []
    free_index = 0
    word_count = len(MNEMONIC_WORDS)
    for pos in range(word_count):
        if pos in fixed:
            candidate.append(fixed[pos])                           # Use locked word at this position
            continue
        candidate.append(free_order[free_index])                   # Fill open position with next free word
        free_index = free_index + 1
    return tuple(candidate)                                        # Tuples are safe to pass between processes

def count_unique_permutations(words) -> int:
    """Count unique permutations, taking duplicate words into account."""
    counts = Counter(words)
    total = factorial(len(words))
    for word in counts:
        total = total // factorial(counts[word])                   # Adjust for repeated words
    return total

def count_raw_permutation_iterations(words) -> int:
    """Count raw itertools.permutations iterations."""
    return factorial(len(words))                                   # itertools.permutations includes duplicate orders

def build_permutation_chunks(free_words, fixed):
    """Yield chunks of complete candidate word orders."""
    chunk = []
    for free_order in permutations(free_words):                    # Generate every free-word order
        candidate_words = build_candidate_words(free_order, fixed) # Combine free order with fixed positions
        chunk.append(candidate_words)
        if len(chunk) < PERMUTATION_CHUNK_SIZE:
            continue
        yield chunk                                                # Send a full batch to workers
        chunk = []
    if chunk:
        yield chunk                                                # Send final partial batch

def check_permutation_chunk(chunk):
    """Check a chunk of candidate mnemonic orders."""
    for candidate_words in chunk:
        mnemonic = make_mnemonic(candidate_words)                  # Convert candidate tuple to mnemonic text
        if not is_valid_bip39(mnemonic):
            continue                                               # Most wrong orders fail checksum
        if address_matches_valid_mnemonic(mnemonic):
            return mnemonic                                        # Correct order found
    return None                                                    # No match in this chunk

def check_original_order():
    """Check whether the entered word order is already correct."""
    mnemonic = make_mnemonic(MNEMONIC_WORDS)
    if address_matches(mnemonic):
        return mnemonic                                            # No recovery needed
    return None

def get_worker_config():
    """Build config passed to multiprocessing workers."""
    return {
        "coin_mode": COIN_MODE,
        "target_addr": TARGET_ADDR,
        "passphrase": PASSPHRASE,
        "mnemonic_words": MNEMONIC_WORDS,
    }

def init_worker(config):
    """Initialize runtime globals inside multiprocessing workers."""
    global COIN_MODE, TARGET_ADDR, PASSPHRASE, MNEMONIC_WORDS
    COIN_MODE = config["coin_mode"]
    TARGET_ADDR = config["target_addr"]
    PASSPHRASE = config["passphrase"]
    MNEMONIC_WORDS = config["mnemonic_words"]

def print_search_params(free_words):
    """Print search configuration."""
    unique_count = count_unique_permutations(free_words)
    raw_count = count_raw_permutation_iterations(free_words)
    print("")
    print("========== Search Parameters ==========")
    print(f"Coin: {COIN_MODE}")
    print(f"Mnemonic word count: {len(MNEMONIC_WORDS)}")
    print(f"Fixed position count: {len(KNOWN_POSITIONS)}")
    print(f"Free word count: {len(free_words)}")
    print(f"Target address: {TARGET_ADDR}")
    print(f"Derivation path: {get_derivation_info()}")
    print(f"Unique free-word orders: {unique_count:,}")
    print(f"Raw permutation iterations: {raw_count:,}")
    print(f"CPU process count: {cpu_count()}")
    print("=======================================")

def print_result(mnemonic):
    """Print recovered mnemonic."""
    print("")
    print("========== FOUND ==========")
    print("Recovered mnemonic:")
    print(mnemonic)
    print("===========================")

def print_not_found():
    """Print possible reasons when no matching order is found."""
    print("")
    print("========== NOT FOUND ==========")
    print("No matching result found.")
    print("Possible reasons:")
    print("1. The address was not generated from these words.")
    print("2. A BIP39 passphrase was used, but the entered passphrase is wrong or empty.")
    print("3. The selected coin is wrong.")
    print("4. The derivation path does not match the wallet.")
    print("5. The target address is not the first address at address index 0.")
    print("6. The mnemonic has a wrong word, missing word, or extra word.")
    print("7. The search space is too large to finish in practical time.")
    print("===============================")

def search_order():
    """Search for the correct mnemonic word order."""
    fixed = build_fixed_positions_zero_based()
    free_words = build_free_words(fixed)
    print_search_params(free_words)
    print("")
    print("Checking whether the entered word order is already correct")
    original_result = check_original_order()
    if original_result is not None:
        return original_result
    print("")
    print("Starting order search")
    print("The window will stay open when the search finishes.")
    chunks = build_permutation_chunks(free_words, fixed)
    worker_config = get_worker_config()
    pool = Pool(cpu_count(), initializer=init_worker, initargs=(worker_config,))
    checked_chunks = 0
    try:
        for result in pool.imap_unordered(check_permutation_chunk, chunks, chunksize=1):
            checked_chunks = checked_chunks + 1
            if checked_chunks % PROGRESS_EVERY_CHUNKS == 0:
                checked_candidates = checked_chunks * PERMUTATION_CHUNK_SIZE
                print(f"Progress: checked about {checked_candidates:,} candidate orders")
            if result is not None:
                pool.terminate()
                pool.join()
                return result
        pool.close()
        pool.join()
        return None
    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
        print("")
        print("Search interrupted by user.")
        return None
    except Exception as error:
        pool.terminate()
        pool.join()
        print("")
        print("Runtime error during search:")
        print(error)
        return None

def main():
    """Main program entry point."""
    try:
        print_header()
        ask_user_inputs()
        errors = collect_input_errors()
        if errors:
            print_input_errors(errors)
            return
        result = search_order()
        if result is not None:
            print_result(result)
            return
        print_not_found()
    finally:
        wait_before_exit()

if __name__ == "__main__":
    main()
