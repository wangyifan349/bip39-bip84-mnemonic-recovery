#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BIP39 / Bitcoin Mnemonic Recovery Tool

This script helps recover a Bitcoin wallet mnemonic in two separate scenarios:

1. Word Order Recovery
   All mnemonic words are correct BIP39 words, but their order is wrong.
   The script generates possible word orders, filters them by BIP39 checksum,
   derives Bitcoin addresses, and compares them with a known target address.

2. Wrong Word Correction
   The mnemonic word order is correct, but one or two words are wrong.
   The script replaces the wrong word positions with every word from the
   official 2048-word BIP39 English word list, filters candidates by BIP39
   checksum, derives Bitcoin addresses, and compares them with a known target
   address.

Important:
- Every candidate is checked with the BIP39 checksum before seed generation.
- Run this script only on an offline, trusted machine.
- Never enter your mnemonic into any website or untrusted software.
- Full order recovery for 12 words can be very slow.
- Full correction of two wrong words can also be very slow.
"""

import getpass
import hashlib
import math
import sys
import time
from collections import Counter
from itertools import combinations, product

try:
    from bip_utils import (
        Bip39Languages,
        Bip39SeedGenerator,
        Bip39WordsListGetter,
        Bip44,
        Bip44Changes,
        Bip44Coins,
        Bip49,
        Bip49Coins,
        Bip84,
        Bip84Coins,
    )

    try:
        from bip_utils import Bip86, Bip86Coins
    except ImportError:
        Bip86 = None
        Bip86Coins = None

except ImportError:
    print("Missing dependency: bip-utils")
    print("Please install it first: pip install bip-utils")
    sys.exit(1)


VALID_WORD_COUNTS = {12, 15, 18, 21, 24}
WORDLIST_SIZE = 2048
PROGRESS_INTERVAL = 10


def load_bip39_words():
    """Load the official English BIP39 word list from bip-utils."""
    try:
        wordlist_object = Bip39WordsListGetter.Instance().GetByLanguage(Bip39Languages.ENGLISH)
    except AttributeError:
        wordlist_object = Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH)

    words = []
    word_to_index = {}

    for index in range(wordlist_object.Length()):
        word = wordlist_object.GetWordAtIdx(index)
        words.append(word)
        word_to_index[word] = index

    return words, word_to_index


def ask_text(prompt):
    """Ask for non-empty text input."""
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Input cannot be empty.")


def ask_int(prompt, default_value, min_value):
    """Ask for an integer input with a default value."""
    while True:
        value = input(f"{prompt} Default {default_value}: ").strip()
        if not value:
            return default_value

        try:
            number = int(value)
        except ValueError:
            print("Please enter an integer.")
            continue

        if number < min_value:
            print(f"Value cannot be less than {min_value}.")
            continue

        return number


def ask_choice(prompt, valid_choices, default_choice):
    """Ask the user to choose one value from a valid set."""
    while True:
        value = input(prompt).strip()
        if not value:
            return default_choice
        if value in valid_choices:
            return value
        print("Invalid choice. Please try again.")


def ask_yes_no(prompt, default_value):
    """Ask a yes/no question."""
    default_text = "Y/n" if default_value else "y/N"

    while True:
        value = input(f"{prompt} [{default_text}]: ").strip().lower()
        if not value:
            return default_value
        if value == "y" or value == "yes":
            return True
        if value == "n" or value == "no":
            return False
        print("Please enter y or n.")


def split_words(text):
    """Normalize mnemonic input into lowercase words."""
    words = []
    parts = text.strip().lower().split()

    for part in parts:
        if part:
            words.append(part)

    return words


def checksum_is_valid(indexes):
    """
    Validate the BIP39 checksum.

    BIP39 encodes each word as an 11-bit index. The full bit stream contains
    entropy bits followed by checksum bits. The checksum is derived from the
    SHA256 hash of the entropy.
    """
    word_count = len(indexes)

    if word_count not in VALID_WORD_COUNTS:
        return False

    bit_string = ""

    for index in indexes:
        bit_string += f"{index:011b}"

    total_bits = word_count * 11
    entropy_bits_count = total_bits * 32 // 33
    checksum_bits_count = entropy_bits_count // 32

    entropy_bits = bit_string[:entropy_bits_count]
    actual_checksum_bits = bit_string[entropy_bits_count:]

    entropy_bytes = int(entropy_bits, 2).to_bytes(entropy_bits_count // 8, "big")
    digest = hashlib.sha256(entropy_bytes).digest()

    digest_bits = ""

    for byte in digest:
        digest_bits += f"{byte:08b}"

    expected_checksum_bits = digest_bits[:checksum_bits_count]

    return actual_checksum_bits == expected_checksum_bits


def get_scheme_context(scheme, network):
    """Return the correct bip-utils derivation context and coin enum."""
    if scheme == "bip44":
        context_class = Bip44
        coin_class = Bip44Coins
    elif scheme == "bip49":
        context_class = Bip49
        coin_class = Bip49Coins
    elif scheme == "bip84":
        context_class = Bip84
        coin_class = Bip84Coins
    elif scheme == "bip86":
        if Bip86 is None or Bip86Coins is None:
            raise RuntimeError("The installed bip-utils version does not support BIP86. Please upgrade bip-utils.")
        context_class = Bip86
        coin_class = Bip86Coins
    else:
        raise ValueError("Unknown derivation scheme.")

    if network == "testnet":
        coin = getattr(coin_class, "BITCOIN_TESTNET")
    else:
        coin = getattr(coin_class, "BITCOIN")

    return context_class, coin


def get_purpose_number(scheme):
    """Return the BIP purpose number used in the derivation path."""
    if scheme == "bip44":
        return 44
    if scheme == "bip49":
        return 49
    if scheme == "bip84":
        return 84
    if scheme == "bip86":
        return 86

    raise ValueError("Unknown derivation scheme.")


def get_change_list(change_mode):
    """Return the selected address chain or chains."""
    change_list = []

    if change_mode == "external":
        change_list.append((0, Bip44Changes.CHAIN_EXT))
    elif change_mode == "internal":
        change_list.append((1, Bip44Changes.CHAIN_INT))
    elif change_mode == "both":
        change_list.append((0, Bip44Changes.CHAIN_EXT))
        change_list.append((1, Bip44Changes.CHAIN_INT))
    else:
        raise ValueError("Unknown change mode.")

    return change_list


def find_address(mnemonic, target_address, scheme, network, account, change_mode, max_index, passphrase):
    """
    Derive Bitcoin addresses from a mnemonic and compare them with the target address.

    The function scans:
    m / purpose' / coin_type' / account' / change / address_index
    """
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    context_class, coin = get_scheme_context(scheme, network)
    account_context = context_class.FromSeed(seed, coin).Purpose().Coin().Account(account)

    purpose = get_purpose_number(scheme)
    coin_type = 1 if network == "testnet" else 0
    change_list = get_change_list(change_mode)

    for change_number, change_enum in change_list:
        change_context = account_context.Change(change_enum)

        for address_index in range(max_index + 1):
            address_context = change_context.AddressIndex(address_index)
            address = address_context.PublicKey().ToAddress()

            if address == target_address:
                path = f"m/{purpose}'/{coin_type}'/{account}'/{change_number}/{address_index}"
                return path, address

    return None, None


def words_to_indexes(words, word_to_index):
    """Convert BIP39 words into their word-list indexes."""
    indexes = []

    for word in words:
        if word not in word_to_index:
            return None

        indexes.append(word_to_index[word])

    return tuple(indexes)


def unique_permutations(items):
    """Generate unique permutations, including cases where duplicate words exist."""
    item_counter = Counter(items)
    current_items = []
    target_length = len(items)

    def backtrack():
        if len(current_items) == target_length:
            yield tuple(current_items)
            return

        for item in list(item_counter.keys()):
            if item_counter[item] == 0:
                continue

            item_counter[item] -= 1
            current_items.append(item)
            yield from backtrack()
            current_items.pop()
            item_counter[item] += 1

    yield from backtrack()


def permutation_count(words):
    """Count unique permutations of the input word list."""
    counter = Counter(words)
    count = math.factorial(len(words))

    for value in counter.values():
        count //= math.factorial(value)

    return count


def typo_candidate_count(words, wrong_count, word_to_index):
    """Estimate the number of candidates in wrong-word correction mode."""
    invalid_positions = []

    for position in range(len(words)):
        if words[position] not in word_to_index:
            invalid_positions.append(position)

    if len(invalid_positions) > wrong_count:
        return 0

    total = 0

    for positions in combinations(range(len(words)), wrong_count):
        valid_position_group = True

        for invalid_position in invalid_positions:
            if invalid_position not in positions:
                valid_position_group = False
                break

        if not valid_position_group:
            continue

        count_for_group = 1

        for position in positions:
            if words[position] in word_to_index:
                count_for_group *= WORDLIST_SIZE - 1
            else:
                count_for_group *= WORDLIST_SIZE

        total += count_for_group

    return total


def print_complexity(mode, words, wrong_count, scheme, network, account, change_mode, max_index, target_address, word_to_index):
    """Print a rough complexity estimate before running recovery."""
    word_count = len(words)
    checksum_bits = word_count // 3
    checksum_divisor = 2 ** checksum_bits
    change_count = len(get_change_list(change_mode))
    addresses_per_candidate = change_count * (max_index + 1)

    print("\nCurrent settings")
    print("-" * 60)
    print(f"Mode: {mode}")
    print(f"Word count: {word_count}")
    print(f"Derivation scheme: {scheme}")
    print(f"Network: {network}")
    print(f"Account index: {account}")
    print(f"Change mode: {change_mode}")
    print(f"Address index range: 0..{max_index}")
    print(f"Target address: {target_address}")
    print("-" * 60)

    print("\nComplexity estimate")
    print("-" * 60)

    if mode == "order":
        candidates = permutation_count(words)
        expected_valid = candidates / checksum_divisor
        expected_derivations = expected_valid * addresses_per_candidate

        print("Recovery type: word order recovery")
        print(f"Raw permutation count: {candidates:,}")
        print(f"BIP39 checksum bits: {checksum_bits}")
        print(f"Theoretical checksum pass rate: 1/{checksum_divisor}")
        print(f"Estimated checksum-valid candidates: {expected_valid:,.2f}")
        print(f"Addresses scanned per checksum-valid candidate: {addresses_per_candidate}")
        print(f"Estimated address derivations: {expected_derivations:,.2f}")
        print("Time complexity: O(P + V × A)")
        print("P = permutations, V = checksum-valid candidates, A = scanned addresses per candidate.")

        if word_count > 12:
            print("Warning: Full order recovery for more than 12 words is usually impractical.")

    else:
        candidates = typo_candidate_count(words, wrong_count, word_to_index)
        expected_valid = candidates / checksum_divisor
        expected_derivations = expected_valid * addresses_per_candidate

        print("Recovery type: wrong word correction")
        print(f"Wrong word count: {wrong_count}")
        print(f"Raw candidate count: {candidates:,}")
        print(f"BIP39 checksum bits: {checksum_bits}")
        print(f"Theoretical checksum pass rate: 1/{checksum_divisor}")
        print(f"Estimated checksum-valid candidates: {expected_valid:,.2f}")
        print(f"Addresses scanned per checksum-valid candidate: {addresses_per_candidate}")
        print(f"Estimated address derivations: {expected_derivations:,.2f}")

        if wrong_count == 1:
            print("Time complexity: O(N × 2048 + V × A)")
        else:
            print("Time complexity: O(C(N,2) × 2048² + V × A)")
            print("Note: Checksum filtering reduces address derivations, but not raw candidate enumeration.")

    print("-" * 60)


def recover_order(words, word_list, word_to_index, target_address, scheme, network, account, change_mode, max_index, passphrase):
    """Recover the correct word order when all input words are valid BIP39 words."""
    indexes = words_to_indexes(words, word_to_index)

    if indexes is None:
        print("\nOrder recovery requires every input word to exist in the BIP39 word list.")
        print("At least one input word is not in the BIP39 word list.")
        return []

    checked_count = 0
    checksum_valid_count = 0
    results = []
    start_time = time.time()
    last_progress_time = start_time

    print("\nStarting word order recovery...")
    print("Tip: Press Ctrl+C to stop.")

    try:
        for candidate_indexes in unique_permutations(indexes):
            checked_count += 1

            # Critical filter: never derive seed or addresses before checksum validation.
            if not checksum_is_valid(candidate_indexes):
                now = time.time()
                if now - last_progress_time >= PROGRESS_INTERVAL:
                    print(f"Progress: checked {checked_count:,} permutations, checksum-valid {checksum_valid_count:,}.")
                    last_progress_time = now
                continue

            checksum_valid_count += 1

            candidate_words = []

            for index in candidate_indexes:
                candidate_words.append(word_list[index])

            mnemonic = " ".join(candidate_words)

            path, address = find_address(
                mnemonic,
                target_address,
                scheme,
                network,
                account,
                change_mode,
                max_index,
                passphrase,
            )

            if address is not None:
                result = {"mnemonic": mnemonic, "path": path, "address": address}
                results.append(result)

                print("\nMatch found")
                print(f"Mnemonic: {mnemonic}")
                print(f"Path: {path}")
                print(f"Address: {address}")

            now = time.time()

            if now - last_progress_time >= PROGRESS_INTERVAL:
                print(f"Progress: checked {checked_count:,} permutations, checksum-valid {checksum_valid_count:,}.")
                last_progress_time = now

    except KeyboardInterrupt:
        print("\nInterrupted by user.")

    elapsed = time.time() - start_time

    print("\nWord order recovery finished")
    print(f"Checked permutations: {checked_count:,}")
    print(f"Checksum-valid candidates: {checksum_valid_count:,}")
    print(f"Elapsed time: {elapsed:.2f} seconds")

    return results


def recover_typo(words, word_list, word_to_index, wrong_count, target_address, scheme, network, account, change_mode, max_index, passphrase):
    """Correct one or two wrong words while keeping the original word order."""
    invalid_positions = []

    for position in range(len(words)):
        if words[position] not in word_to_index:
            invalid_positions.append(position)

    if len(invalid_positions) > wrong_count:
        print("\nRecovery is impossible with the selected wrong word count.")
        print(f"Invalid BIP39 word count: {len(invalid_positions)}")
        print(f"Selected wrong word count: {wrong_count}")
        return []

    checked_count = 0
    checksum_valid_count = 0
    results = []
    start_time = time.time()
    last_progress_time = start_time

    print("\nStarting wrong word correction...")
    print("Tip: Press Ctrl+C to stop.")
    print("Note: Every candidate is filtered by BIP39 checksum before address derivation.")

    try:
        for positions in combinations(range(len(words)), wrong_count):
            valid_position_group = True

            # Any word that is not in the BIP39 list must be one of the corrected positions.
            for invalid_position in invalid_positions:
                if invalid_position not in positions:
                    valid_position_group = False
                    break

            if not valid_position_group:
                continue

            replacement_lists = []

            for position in positions:
                replacements = []
                original_word = words[position]

                for candidate_word in word_list:
                    if original_word in word_to_index and candidate_word == original_word:
                        continue

                    replacements.append(candidate_word)

                replacement_lists.append(replacements)

            for replacement_tuple in product(*replacement_lists):
                checked_count += 1
                candidate_words = []

                for word in words:
                    candidate_words.append(word)

                replacement_index = 0

                for position in positions:
                    candidate_words[position] = replacement_tuple[replacement_index]
                    replacement_index += 1

                candidate_indexes = words_to_indexes(candidate_words, word_to_index)

                if candidate_indexes is None:
                    continue

                # Critical filter: never derive seed or addresses before checksum validation.
                if not checksum_is_valid(candidate_indexes):
                    now = time.time()
                    if now - last_progress_time >= PROGRESS_INTERVAL:
                        print(f"Progress: checked {checked_count:,} candidates, checksum-valid {checksum_valid_count:,}.")
                        last_progress_time = now
                    continue

                checksum_valid_count += 1
                mnemonic = " ".join(candidate_words)

                path, address = find_address(
                    mnemonic,
                    target_address,
                    scheme,
                    network,
                    account,
                    change_mode,
                    max_index,
                    passphrase,
                )

                if address is not None:
                    result = {
                        "mnemonic": mnemonic,
                        "path": path,
                        "address": address,
                        "positions": positions,
                    }

                    results.append(result)

                    shown_positions = []

                    for position in positions:
                        shown_positions.append(position + 1)

                    print("\nMatch found")
                    print(f"Mnemonic: {mnemonic}")
                    print(f"Path: {path}")
                    print(f"Address: {address}")
                    print(f"Corrected positions: {shown_positions}")

                now = time.time()

                if now - last_progress_time >= PROGRESS_INTERVAL:
                    print(f"Progress: checked {checked_count:,} candidates, checksum-valid {checksum_valid_count:,}.")
                    last_progress_time = now

    except KeyboardInterrupt:
        print("\nInterrupted by user.")

    elapsed = time.time() - start_time

    print("\nWrong word correction finished")
    print(f"Checked candidates: {checked_count:,}")
    print(f"Checksum-valid candidates: {checksum_valid_count:,}")
    print(f"Elapsed time: {elapsed:.2f} seconds")

    return results


def print_results(results):
    """Print the final recovery result."""
    print("\nFinal result")
    print("=" * 60)

    if len(results) == 0:
        print("No matching result was found.")
        print("\nPossible reasons:")
        print("1. The derivation scheme is wrong, for example the wallet is not BIP84.")
        print("2. The address index range is too small.")
        print("3. The change chain is wrong. Try scanning both external and internal chains.")
        print("4. The account index is not 0.")
        print("5. A BIP39 passphrase was used but was not entered, or it was entered incorrectly.")
        print("6. The target address does not belong to this mnemonic.")
    else:
        print(f"Found {len(results)} matching result(s).")

        result_number = 1

        for result in results:
            print(f"\nResult {result_number}")
            print(f"Mnemonic: {result['mnemonic']}")
            print(f"Path: {result['path']}")
            print(f"Address: {result['address']}")

            if "positions" in result:
                shown_positions = []

                for position in result["positions"]:
                    shown_positions.append(position + 1)

                print(f"Corrected positions: {shown_positions}")

            result_number += 1

    print("=" * 60)


def ask_config():
    """Collect recovery settings from the user."""
    print("\nSelect recovery mode")
    print("1. Recover word order: all words are correct, but the order is wrong")
    print("2. Correct wrong words: word order is correct, but 1 or 2 words are wrong")

    mode_choice = ask_choice("Enter 1 or 2: ", {"1", "2"}, "1")
    mode = "order" if mode_choice == "1" else "typo"

    mnemonic_text = ask_text("\nEnter mnemonic words separated by spaces: ")
    words = split_words(mnemonic_text)

    if len(words) not in VALID_WORD_COUNTS:
        print(f"Warning: Current word count is {len(words)}. Standard BIP39 word counts are 12, 15, 18, 21, or 24.")

    target_address = ask_text("Enter the known BTC receiving address: ")

    print("\nSelect derivation scheme")
    print("1. BIP84, native SegWit, usually bc1q address, default")
    print("2. BIP49, nested SegWit, usually address starts with 3")
    print("3. BIP44, legacy, usually address starts with 1")
    print("4. BIP86, Taproot, usually bc1p address")

    scheme_choice = ask_choice("Choose one, default 1: ", {"1", "2", "3", "4"}, "1")

    if scheme_choice == "1":
        scheme = "bip84"
    elif scheme_choice == "2":
        scheme = "bip49"
    elif scheme_choice == "3":
        scheme = "bip44"
    else:
        scheme = "bip86"

    print("\nSelect network")
    print("1. mainnet, Bitcoin main network, default")
    print("2. testnet, Bitcoin test network")

    network_choice = ask_choice("Choose one, default 1: ", {"1", "2"}, "1")
    network = "testnet" if network_choice == "2" else "mainnet"

    print("\nSelect address chain")
    print("1. external, receiving chain m/.../0/i, default")
    print("2. internal, change chain m/.../1/i")
    print("3. both, scan both receiving and change chains")

    change_choice = ask_choice("Choose one, default 1: ", {"1", "2", "3"}, "1")

    if change_choice == "1":
        change_mode = "external"
    elif change_choice == "2":
        change_mode = "internal"
    else:
        change_mode = "both"

    account = ask_int("\nEnter account index", 0, 0)
    max_index = ask_int("Enter max address index. The program will scan from 0 to this value", 20, 0)
    use_passphrase = ask_yes_no("\nUse BIP39 passphrase", False)

    if use_passphrase:
        passphrase = getpass.getpass("Enter BIP39 passphrase. Input will be hidden: ")
    else:
        passphrase = ""

    wrong_count = 0

    if mode == "typo":
        print("\nSelect wrong word count")
        print("1. One wrong word")
        print("2. Two wrong words, full 2048-word scan")

        wrong_choice = ask_choice("Enter 1 or 2: ", {"1", "2"}, "1")
        wrong_count = int(wrong_choice)

    return mode, words, target_address, scheme, network, account, change_mode, max_index, passphrase, wrong_count


def main():
    """Run the interactive recovery program."""
    print("=" * 60)
    print("BIP39 / Bitcoin Mnemonic Recovery Tool")
    print("Mode 1: Recover word order")
    print("Mode 2: Correct one or two wrong words")
    print("Security note: Run this only offline, locally, and in a trusted environment")
    print("=" * 60)

    word_list, word_to_index = load_bip39_words()

    while True:
        config = ask_config()

        mode = config[0]
        words = config[1]
        target_address = config[2]
        scheme = config[3]
        network = config[4]
        account = config[5]
        change_mode = config[6]
        max_index = config[7]
        passphrase = config[8]
        wrong_count = config[9]

        print_complexity(
            mode,
            words,
            wrong_count,
            scheme,
            network,
            account,
            change_mode,
            max_index,
            target_address,
            word_to_index,
        )

        should_start = ask_yes_no("\nStart recovery", True)

        if not should_start:
            print("Recovery cancelled.")
            results = []
        elif mode == "order":
            results = recover_order(
                words,
                word_list,
                word_to_index,
                target_address,
                scheme,
                network,
                account,
                change_mode,
                max_index,
                passphrase,
            )
        else:
            results = recover_typo(
                words,
                word_list,
                word_to_index,
                wrong_count,
                target_address,
                scheme,
                network,
                account,
                change_mode,
                max_index,
                passphrase,
            )

        print_results(results)

        run_again = ask_yes_no("\nRun another recovery", False)

        if not run_again:
            break

    input("\nProgram finished. Press Enter to exit...")


if __name__ == "__main__":
    main()
