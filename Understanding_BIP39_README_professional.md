# Understanding BIP39

A compact technical guide to BIP39 mnemonic code, entropy, checksum construction, wordlist indexing, seed derivation, passphrases, HD wallets, derivation paths, and relevant cryptographic background.

## Table of Contents

- [1. Scope](#1-scope)
- [2. Position in Wallet Architecture](#2-position-in-wallet-architecture)
- [3. Core Terminology](#3-core-terminology)
- [4. Cryptographic Background](#4-cryptographic-background)
- [5. Entropy Requirements](#5-entropy-requirements)
- [6. Mnemonic Generation](#6-mnemonic-generation)
- [7. Checksum Construction](#7-checksum-construction)
- [8. Wordlist and 11-bit Indexing](#8-wordlist-and-11-bit-indexing)
- [9. Mnemonic Validation](#9-mnemonic-validation)
- [10. Seed Derivation](#10-seed-derivation)
- [11. Passphrase Semantics](#11-passphrase-semantics)
- [12. BIP39 and BIP32](#12-bip39-and-bip32)
- [13. Derivation Paths](#13-derivation-paths)
- [14. Address Standards Related to BIP39](#14-address-standards-related-to-bip39)
- [15. Complexity and Security Strength](#15-complexity-and-security-strength)
- [16. Implementation Notes](#16-implementation-notes)
- [17. Reference Algorithms](#17-reference-algorithms)
- [18. Security Considerations](#18-security-considerations)
- [19. Glossary](#19-glossary)
- [20. References](#20-references)

## 1. Scope

BIP39, titled *Mnemonic code for generating deterministic keys*, defines a method for converting cryptographic entropy into a human-readable mnemonic sentence and then converting that mnemonic sentence into a binary seed. The seed is commonly used as input material for hierarchical deterministic wallet systems such as BIP32. BIP39 does not define addresses, transaction formats, elliptic-curve signing, account discovery, network parameters, or derivation paths. It defines the mnemonic layer and the seed derivation layer.

The main boundary is:

```text
BIP39:
entropy -> mnemonic sentence -> seed

Outside BIP39:
seed -> master key -> child keys -> public keys -> addresses -> transactions
```

A correct BIP39 implementation must handle entropy length, checksum bits, wordlist indexing, Unicode normalization, PBKDF2-HMAC-SHA512 parameters, and seed output length exactly.

## 2. Position in Wallet Architecture

Modern cryptocurrency wallets are usually layered systems. BIP39 is one layer in that system.

```text
Cryptographically secure random number generator
    |
    v
Entropy
    |
    v
BIP39 mnemonic generation
    |
    v
Mnemonic sentence
    |
    v
BIP39 seed derivation
    |
    v
512-bit seed
    |
    v
BIP32 hierarchical deterministic wallet
    |
    v
Extended private keys / extended public keys
    |
    v
BIP44 / BIP49 / BIP84 / BIP86 derivation paths
    |
    v
Private keys / public keys
    |
    v
Addresses and signatures
```

The mnemonic sentence is designed for backup and recovery. The seed is designed for deterministic key generation. The derivation path determines which branch of the HD wallet tree is used for a specific coin, account, address type, and address index.

## 3. Core Terminology

| Term | Meaning |
|---|---|
| Entropy | Random binary input used as the root material for mnemonic generation. |
| ENT | Entropy length in bits. Valid BIP39 values are 128, 160, 192, 224, and 256. |
| Checksum | Short bit sequence derived from `SHA256(entropy)`. |
| CS | Checksum length in bits. In BIP39, `CS = ENT / 32`. |
| Mnemonic sentence | Ordered sequence of words generated from entropy plus checksum. |
| Wordlist | Fixed list of 2048 words. Each word corresponds to an 11-bit index. |
| Seed | 512-bit output produced by PBKDF2-HMAC-SHA512 from the mnemonic and optional passphrase. |
| Passphrase | Optional user-supplied string used as part of the PBKDF2 salt. |
| PBKDF2 | Password-Based Key Derivation Function 2. |
| HMAC-SHA512 | HMAC construction using SHA-512 as the underlying hash function. |
| BIP32 | Hierarchical deterministic wallet standard that can derive a key tree from a seed. |
| Derivation path | A notation such as `m/84'/0'/0'/0/0` describing how to derive a specific child key. |
| Hardened derivation | BIP32 child-key derivation mode marked with `'` or `h`, e.g. `84'`. |
| xprv / xpub | Extended private/public keys used in BIP32-style HD wallets. |
| zpub / ypub | Common version-prefix conventions used by some wallets to indicate script/address type. |

## 4. Cryptographic Background

### 4.1 Entropy

In cryptography, entropy measures unpredictability. A 128-bit uniformly random value has a search space of `2^128` possible values. A 256-bit uniformly random value has a search space of `2^256` possible values. These values are computationally infeasible to exhaustively search when generated correctly.

### 4.2 Cryptographically Secure Random Number Generator

A cryptographically secure random number generator, usually abbreviated CSPRNG, is a random source designed to be unpredictable even against an attacker with substantial computational power. BIP39 security depends directly on the quality of the entropy. If the entropy is weak, the mnemonic is weak.

### 4.3 Hash Function

A cryptographic hash function maps input data of arbitrary length to a fixed-length digest. BIP39 uses SHA-256 to compute the checksum. SHA-256 outputs 256 bits. BIP39 does not use the full SHA-256 digest as the checksum; it uses only the first `ENT / 32` bits.

### 4.4 HMAC

HMAC is a keyed hash construction. It combines a cryptographic hash function with a secret key to produce a message authentication code. BIP39 uses HMAC-SHA512 inside PBKDF2.

### 4.5 Key Derivation Function

A key derivation function, or KDF, derives cryptographic key material from input material. BIP39 uses PBKDF2-HMAC-SHA512 to derive a 512-bit seed from the mnemonic sentence and optional passphrase.

### 4.6 Brute Force Complexity

Brute force complexity describes the cost of trying all possible candidates. For uniformly random entropy of length `n`, the search space is `2^n`. A 12-word BIP39 mnemonic corresponds to 128 bits of entropy plus 4 checksum bits, so its entropy strength is 128 bits, not 132 bits. A 24-word mnemonic corresponds to 256 bits of entropy plus 8 checksum bits, so its entropy strength is 256 bits, not 264 bits.

## 5. Entropy Requirements

BIP39 supports exactly five entropy lengths.

| ENT | CS = ENT / 32 | ENT + CS | Word Count |
|---:|---:|---:|---:|
| 128 | 4 | 132 | 12 |
| 160 | 5 | 165 | 15 |
| 192 | 6 | 198 | 18 |
| 224 | 7 | 231 | 21 |
| 256 | 8 | 264 | 24 |

The formulas are:

```text
CS = ENT / 32
MS = (ENT + CS) / 11
```

Where `MS` is the mnemonic sentence length in words. Entropy must be generated from a CSPRNG. User-created phrases, manually selected words, timestamps, names, low-entropy strings, predictable counters, and non-cryptographic random functions are not appropriate entropy sources.

## 6. Mnemonic Generation

Mnemonic generation is the process of converting entropy into an ordered sequence of words.

The high-level algorithm is:

```text
1. Generate ENT bits of entropy.
2. Compute SHA256(entropy).
3. Take the first ENT / 32 bits of the SHA-256 hash as checksum.
4. Append checksum bits to the entropy bits.
5. Split the combined bit string into 11-bit groups.
6. Convert each 11-bit group into an integer from 0 to 2047.
7. Use each integer as an index into the 2048-word BIP39 wordlist.
8. Join the resulting words into a mnemonic sentence.
```

Compact flow:

```text
entropy -> SHA256(entropy) -> checksum -> entropy || checksum -> 11-bit groups -> word indices -> mnemonic
```

Example structure for 128-bit entropy:

```text
128 entropy bits + 4 checksum bits = 132 bits
132 bits / 11 = 12 words
```

Example structure for 256-bit entropy:

```text
256 entropy bits + 8 checksum bits = 264 bits
264 bits / 11 = 24 words
```

## 7. Checksum Construction

The checksum is derived from the entropy, not from the words.

```text
hash = SHA256(entropy)
checksum = first ENT / 32 bits of hash
```

The checksum length is intentionally short. It is not a cryptographic authentication tag. It is a structural validity check for detecting many transcription or word-selection errors. The checksum bits are appended to the entropy bits before splitting into 11-bit groups.

For a 12-word mnemonic:

```text
ENT = 128
CS = 4
Total = 132
```

For a 24-word mnemonic:

```text
ENT = 256
CS = 8
Total = 264
```

Checksum bits contribute to mnemonic validity but not to entropy strength. The effective preimage search space is determined by the entropy length.

## 8. Wordlist and 11-bit Indexing

The BIP39 wordlist contains exactly 2048 words. Since `2^11 = 2048`, each 11-bit group maps exactly to one wordlist index.

```text
00000000000 -> 0
00000000001 -> 1
00000000010 -> 2
...
11111111111 -> 2047
```

The English wordlist begins with:

```text
abandon
ability
able
about
above
absent
absorb
abstract
absurd
abuse
access
accident
```

The final word is:

```text
zoo
```

The wordlist order is part of the algorithm. A valid implementation must use the exact list and exact ordering. The word index is not computed by sorting, hashing, or translating words. It is a direct lookup in the fixed wordlist.

## 9. Mnemonic Validation

Mnemonic validation reverses the mnemonic-generation process.

A validator should:

```text
1. Split the mnemonic sentence into words.
2. Verify that the word count is one of 12, 15, 18, 21, or 24.
3. Verify that every word exists in the selected BIP39 wordlist.
4. Convert each word to its 11-bit index.
5. Concatenate all 11-bit groups.
6. Split the bit string into entropy bits and checksum bits.
7. Compute SHA256(entropy).
8. Compare the extracted checksum with the expected checksum.
```

The bit split is derived from the total bit length:

```text
ENT = total_bits * 32 / 33
CS = total_bits / 33
```

For 12 words:

```text
12 * 11 = 132 total bits
ENT = 132 * 32 / 33 = 128
CS = 132 / 33 = 4
```

## 10. Seed Derivation

BIP39 derives the seed with PBKDF2-HMAC-SHA512.

Parameters:

| Parameter | Value |
|---|---|
| KDF | PBKDF2 |
| PRF | HMAC-SHA512 |
| Password | Mnemonic sentence |
| Salt | `"mnemonic" + passphrase` |
| Iterations | 2048 |
| Output length | 64 bytes |
| Output size | 512 bits |
| Encoding | UTF-8 |
| Normalization | NFKD |

Formula:

```text
seed = PBKDF2-HMAC-SHA512(
    password = NFKD(mnemonic),
    salt = NFKD("mnemonic" + passphrase),
    iterations = 2048,
    dkLen = 64
)
```

The seed is binary key material. It is normally represented as 64 bytes or 128 hexadecimal characters. The seed is not the same as the mnemonic. The seed is not the same as a private key. It is input material for a deterministic wallet system.

## 11. Passphrase Semantics

The passphrase is an optional string used in seed derivation. It is not a wordlist index and is not appended as an additional mnemonic word. It changes the PBKDF2 salt.

```text
salt = "mnemonic" + passphrase
```

If the passphrase is empty:

```text
salt = "mnemonic"
```

If the passphrase is `example`:

```text
salt = "mnemonicexample"
```

The same mnemonic with different passphrases produces different seeds:

```text
mnemonic + ""        -> seed A
mnemonic + "alpha"   -> seed B
mnemonic + "beta"    -> seed C
```

Both mnemonic and passphrase are normalized with UTF-8 NFKD before PBKDF2. This matters for passphrases containing accents, composed Unicode characters, compatibility forms, CJK characters, or non-ASCII whitespace.

## 12. BIP39 and BIP32

BIP39 and BIP32 are distinct standards.

BIP39 defines:

```text
entropy -> mnemonic -> seed
```

BIP32 defines:

```text
seed -> master extended private key -> child extended keys
```

BIP32 produces an HD wallet tree. Each node in the tree contains key material and chain code. Extended private keys and extended public keys allow deterministic derivation of child keys.

A simplified BIP32 structure:

```text
m
├── m/0
├── m/1
└── m/2
    ├── m/2/0
    ├── m/2/1
    └── m/2/2
```

In path notation, `m` represents the master node. Each number represents a child index. Hardened derivation is marked with an apostrophe:

```text
m/0'
m/44'/0'/0'
```

## 13. Derivation Paths

A derivation path specifies how to derive a particular key from the BIP32 master node. BIP39 does not define these paths, but BIP39-based wallets commonly use them.

General BIP44-style structure:

```text
m / purpose' / coin_type' / account' / change / address_index
```

Meaning:

| Component | Meaning |
|---|---|
| `m` | Master node. |
| `purpose'` | Standard or address-purpose namespace, usually hardened. |
| `coin_type'` | Coin identifier, usually defined by SLIP-0044, hardened. |
| `account'` | Account number, hardened. |
| `change` | `0` for external receiving addresses, `1` for internal change addresses. |
| `address_index` | Address index under the selected branch. |

Common Bitcoin mainnet examples:

| Standard | Path Example | Address Type | Common Prefix |
|---|---|---|---|
| BIP44 | `m/44'/0'/0'/0/0` | Legacy P2PKH | `1...` |
| BIP49 | `m/49'/0'/0'/0/0` | Nested SegWit P2SH-P2WPKH | `3...` |
| BIP84 | `m/84'/0'/0'/0/0` | Native SegWit P2WPKH | `bc1q...` |
| BIP86 | `m/86'/0'/0'/0/0` | Taproot P2TR | `bc1p...` |

For Bitcoin testnet, coin type is commonly `1'`:

```text
m/84'/1'/0'/0/0
```

For Ethereum, a common path is:

```text
m/44'/60'/0'/0/0
```

Derivation path compatibility is essential for wallet recovery. The same BIP39 mnemonic and passphrase can produce many different addresses depending on the derivation path, coin type, script type, and account index.

## 14. Address Standards Related to BIP39

BIP39 does not generate addresses directly. Address generation happens after BIP32 key derivation and depends on the script or address standard.

| Layer | Standard | Role |
|---|---|---|
| Mnemonic and seed | BIP39 | Converts entropy to mnemonic and seed. |
| HD key tree | BIP32 | Derives master and child keys. |
| Account hierarchy | BIP44 | Defines multi-account path convention. |
| Nested SegWit path | BIP49 | Defines path convention for P2SH-wrapped SegWit. |
| Native SegWit path | BIP84 | Defines path convention for P2WPKH. |
| Taproot path | BIP86 | Defines path convention for single-key P2TR. |

A full wallet recovery context includes:

```text
mnemonic
passphrase
network
coin type
account
derivation path
script type
address index range
gap limit / account discovery rule
```

## 15. Complexity and Security Strength

### 15.1 Entropy Search Space

The theoretical brute-force search space is determined by `ENT`, not by the total mnemonic bit length including checksum.

| Words | ENT | Search Space |
|---:|---:|---:|
| 12 | 128 bits | `2^128` |
| 15 | 160 bits | `2^160` |
| 18 | 192 bits | `2^192` |
| 21 | 224 bits | `2^224` |
| 24 | 256 bits | `2^256` |

The checksum reduces the number of valid word sequences but does not increase entropy strength.

### 15.2 Word Sequence Space

A raw 12-word sequence over a 2048-word list has:

```text
2048^12 = (2^11)^12 = 2^132
```

But only `2^128` of those correspond to valid 128-bit entropy values because 4 bits are checksum bits.

A raw 24-word sequence has:

```text
2048^24 = (2^11)^24 = 2^264
```

But only `2^256` of those correspond to valid 256-bit entropy values because 8 bits are checksum bits.

### 15.3 PBKDF2 Cost

BIP39 uses 2048 PBKDF2 iterations. This adds computational cost to each mnemonic-to-seed attempt. Its main role is slowing repeated guessing attempts, especially when a passphrase is used. The primary security of a generated mnemonic still comes from entropy strength.

### 15.4 Passphrase Complexity

If a passphrase is used, the effective brute-force cost depends on both the mnemonic entropy and the passphrase entropy. A high-entropy passphrase can add meaningful security. A low-entropy passphrase adds limited resistance against guessing.

## 16. Implementation Notes

### 16.1 Byte-to-Bit Order

When converting entropy bytes to bits, preserve most-significant-bit-first order per byte.

Example:

```text
0xA3 = 10100011
```

The bit sequence is:

```text
1 0 1 0 0 0 1 1
```

### 16.2 11-bit Group Parsing

After appending checksum bits, split the bit string into consecutive 11-bit groups without padding.

```text
combined_bits = entropy_bits || checksum_bits
groups = split(combined_bits, 11)
```

Every group becomes an integer index from 0 to 2047.

### 16.3 Wordlist Lookup

Wordlist lookup must use exact words and exact ordering. Implementations should avoid locale-dependent sorting, case conversion, fuzzy matching, or translation during the cryptographic step.

### 16.4 Unicode Normalization

Before seed derivation, both mnemonic and passphrase must be normalized using NFKD and encoded as UTF-8. This is a compatibility requirement, not a display preference.

```text
password = UTF8(NFKD(mnemonic))
salt = UTF8(NFKD("mnemonic" + passphrase))
```

### 16.5 Whitespace Handling

A strict implementation should define how it handles leading spaces, trailing spaces, multiple spaces, newlines, tabs, and non-ASCII whitespace. Internal wallet handling may normalize input for usability, but seed derivation must be deterministic.

### 16.6 Test Vectors

Implementations should be verified against official BIP39 test vectors. Test vectors normally include entropy, mnemonic, seed, and sometimes downstream extended keys. Verification should include both empty and non-empty passphrase cases.

### 16.7 Library Boundary

A BIP39 library should clearly separate:

```text
entropy generation
entropy-to-mnemonic encoding
mnemonic validation
mnemonic-to-seed derivation
BIP32 key derivation
address generation
```

Combining these layers without explicit boundaries makes testing and security review harder.

## 17. Reference Algorithms

### 17.1 Entropy to Mnemonic

```text
function entropy_to_mnemonic(entropy_bytes, wordlist):
    ENT = bit_length(entropy_bytes)

    if ENT not in [128, 160, 192, 224, 256]:
        error("invalid entropy length")

    hash_bytes = SHA256(entropy_bytes)

    CS = ENT / 32

    entropy_bits = bytes_to_bits_msb_first(entropy_bytes)
    hash_bits = bytes_to_bits_msb_first(hash_bytes)

    checksum_bits = first_bits(hash_bits, CS)

    combined_bits = entropy_bits || checksum_bits

    groups = split_into_groups(combined_bits, 11)

    words = []

    for group in groups:
        index = bits_to_integer(group)
        words.append(wordlist[index])

    return join(words, " ")
```

### 17.2 Mnemonic Validation

```text
function validate_mnemonic(mnemonic, wordlist):
    words = split_words(mnemonic)

    if len(words) not in [12, 15, 18, 21, 24]:
        return false

    bits = ""

    for word in words:
        if word not in wordlist:
            return false

        index = wordlist_index(word)
        bits += integer_to_11_bit_binary(index)

    total_bits = len(bits)

    CS = total_bits / 33
    ENT = total_bits - CS

    entropy_bits = bits[0:ENT]
    checksum_bits = bits[ENT:ENT+CS]

    entropy_bytes = bits_to_bytes(entropy_bits)

    hash_bits = bytes_to_bits_msb_first(SHA256(entropy_bytes))
    expected_checksum = first_bits(hash_bits, CS)

    return checksum_bits == expected_checksum
```

### 17.3 Mnemonic to Seed

```text
function mnemonic_to_seed(mnemonic, passphrase):
    normalized_mnemonic = NFKD(mnemonic)
    normalized_passphrase = NFKD(passphrase)

    password = UTF8(normalized_mnemonic)
    salt = UTF8("mnemonic" + normalized_passphrase)

    return PBKDF2_HMAC_SHA512(
        password = password,
        salt = salt,
        iterations = 2048,
        output_length = 64
    )
```

### 17.4 Seed to BIP32 Master Node

BIP32 is outside BIP39, but common wallet architecture continues as follows:

```text
function seed_to_bip32_master(seed):
    I = HMAC_SHA512(key = "Bitcoin seed", data = seed)

    IL = left_32_bytes(I)
    IR = right_32_bytes(I)

    master_private_key = IL
    master_chain_code = IR

    return master_private_key, master_chain_code
```

This simplified description omits curve-order validation and serialization details. Full BIP32 implementations must handle invalid key material, extended key version bytes, child number, depth, parent fingerprint, chain code, and key serialization.

## 18. Security Considerations

### 18.1 Mnemonic Storage

A mnemonic sentence is sensitive key material. It should be stored in a form that matches the user's threat model. Common backup media include paper, engraved metal, stamped metal, and hardware-wallet backup cards.

### 18.2 Exposure Channels

Mnemonic exposure can occur through screenshots, cloud backups, clipboard logs, browser extensions, malware, cameras, OCR, printer memory, typed input logs, or compromised websites. Seed generation and mnemonic handling are best performed in trusted environments.

### 18.3 Entropy Generation

Entropy should not be generated using non-cryptographic pseudo-random functions, timestamps, user names, device names, predictable counters, browser `Math.random()`, or manually chosen phrases. Use a CSPRNG.

### 18.4 Passphrase Handling

A passphrase changes the seed. Losing it changes recoverability. If a passphrase is part of the wallet setup, it must be backed up and protected with the same seriousness as the mnemonic.

### 18.5 Recovery Compatibility

Recovering a wallet requires more than BIP39 in many practical cases. The recovery software must use the same seed derivation, network, derivation path, account index, and address type to find the same addresses.

### 18.6 Verification

Wallet software should verify generated mnemonics against checksum rules and should verify seed generation against known test vectors. Security-critical code should be reviewed, tested, and minimized.

## 19. Glossary

**Address**: A representation of a spending condition or public-key-derived destination on a blockchain. BIP39 does not define addresses.

**BIP**: Bitcoin Improvement Proposal, a document format for proposing Bitcoin-related standards and processes.

**BIP32**: Hierarchical deterministic wallet standard for deriving a tree of keys from a seed.

**BIP39**: Standard for mnemonic code generation and seed derivation.

**BIP44**: Path convention for multi-account deterministic wallets.

**BIP49**: Path convention for nested SegWit P2SH-P2WPKH accounts.

**BIP84**: Path convention for native SegWit P2WPKH accounts.

**BIP86**: Path convention for single-key Taproot P2TR accounts.

**Checksum**: Short bit sequence derived from `SHA256(entropy)` and appended to entropy before word mapping.

**Coin Type**: Hardened path component identifying a cryptocurrency or network, commonly assigned by SLIP-0044.

**CSPRNG**: Cryptographically Secure Random Number Generator.

**Derivation Path**: String notation describing a sequence of child-key derivations, such as `m/84'/0'/0'/0/0`.

**Entropy**: Random source material used to generate the mnemonic.

**Extended Key**: BIP32 key object containing key material plus chain code and metadata.

**Hardened Derivation**: BIP32 derivation mode that prevents certain public-key-only derivation relationships and is marked with `'`.

**HD Wallet**: Hierarchical Deterministic Wallet; a wallet that derives many keys from a single root.

**HMAC**: Hash-based Message Authentication Code.

**KDF**: Key Derivation Function.

**Mnemonic Sentence**: Ordered sequence of BIP39 words representing entropy plus checksum.

**NFKD**: Unicode Normalization Form Compatibility Decomposition.

**Passphrase**: Optional string used in the BIP39 PBKDF2 salt.

**PBKDF2**: Password-Based Key Derivation Function 2.

**Private Key**: Secret scalar used to authorize spending or sign messages.

**Public Key**: Value derived from a private key, usually used to verify signatures or construct addresses.

**Seed**: 512-bit output of BIP39 seed derivation.

**SHA-256**: Cryptographic hash function used by BIP39 for checksum generation.

**SHA-512**: Cryptographic hash function used inside HMAC-SHA512 for BIP39 seed derivation.

**Wordlist**: Fixed ordered list of 2048 words used by BIP39.

## 20. References

- BIP39: Mnemonic code for generating deterministic keys  
  https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

- BIP39 English wordlist  
  https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

- BIP32: Hierarchical Deterministic Wallets  
  https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

- BIP44: Multi-Account Hierarchy for Deterministic Wallets  
  https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

- BIP49: Derivation scheme for P2WPKH-nested-in-P2SH based accounts  
  https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki

- BIP84: Derivation scheme for P2WPKH based accounts  
  https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki

- BIP86: Key Derivation for Single Key P2TR Outputs  
  https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki

- SLIP-0044: Registered coin types for BIP44  
  https://github.com/satoshilabs/slips/blob/master/slip-0044.md
