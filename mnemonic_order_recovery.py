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

       This means those words must appear next to each other in that exact order,
       but their final position is unknown.

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


BENCHMARK_LIMIT = 10_000          # 正式搜索前，先测试多少个排列来估算速度
PROGRESS_INTERVAL = 100_000       # 正式搜索时，每检查多少个排列打印一次进度


def is_valid_mnemonic(words_or_text) -> bool:
    """
    Return True if the given word order is a valid BIP39 English mnemonic.
    """

    mnemonic = (
        " ".join(words_or_text)   # 如果传进来的是列表，就拼成完整助记词字符串
        if isinstance(words_or_text, list)
        else str(words_or_text)   # 如果本来就是字符串，就直接转成字符串
    )

    return Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic)  # 检查 BIP39 checksum 是否有效


def format_int(num: int) -> str:
    return f"{num:,}"             # 把大数字格式化成 1,000,000 这种形式


def format_duration(seconds: float) -> str:
    minute = 60                   # 1 分钟的秒数
    hour = 60 * minute            # 1 小时的秒数
    day = 24 * hour               # 1 天的秒数
    year = 365 * day              # 1 年按 365 天估算

    if seconds < minute:
        return f"{seconds:.2f} seconds"

    if seconds < hour:
        return f"{seconds / minute:.2f} minutes"

    if seconds < day:
        return f"{seconds / hour:.2f} hours"

    if seconds < year:
        return f"{seconds / day:.2f} days"

    years = seconds / year        # 超过一年时，换算成年
    return f"{years:.2f} years" if years < 1_000 else f"{years:.2e} years"


def factorial_permutation_count(unit_counter: Counter) -> int:
    """
    Count permutations of units.

    Unit examples:
        ("apple",)
        ("apple", "banana")
    """

    total = math.factorial(sum(unit_counter.values()))  # 先计算所有单位的阶乘数量，例如 n!

    for count in unit_counter.values():
        total //= math.factorial(count)                 # 如果有重复单位，要除掉重复排列数量

    return total


def count_candidate_orders(unit_counter: Counter, word_count: int, fixed_map: dict) -> int:
    """
    Count the exact number of candidate orders after applying clues.

    Clues:
        1. Fixed positions
        2. Adjacent word groups
        3. Duplicate words
    """

    all_units_are_single_words = all(len(unit) == 1 for unit in unit_counter)  # 判断是否没有连续词组

    if not fixed_map:
        return factorial_permutation_count(unit_counter)                      # 没有固定位置时，直接用排列公式

    if all_units_are_single_words:
        return factorial_permutation_count(unit_counter)                      # 只有单词，没有连续词组，也可以直接用排列公式

    unit_keys = tuple(unit_counter.keys())                                    # 所有可以摆放的单位，可能是单词，也可能是词组
    fixed_positions = set(fixed_map)                                          # 已经固定的位置，后面不能再填别的词
    start_counts = tuple(unit_counter[unit] for unit in unit_keys)            # 每种单位还剩多少个

    @lru_cache(maxsize=None)                                                   # 缓存递归结果，避免重复计算同一状态
    def count_from(position: int, counts: tuple[int, ...]) -> int:
        while position < word_count and position in fixed_positions:
            position += 1                                                      # 跳过已经固定好的位置

        if position == word_count:
            return 1 if sum(counts) == 0 else 0                                # 所有位置填完，并且所有单位也用完，才算一种有效排列

        total = 0                                                              # 从当前位置开始，累计可行排列数量

        for unit_index, unit in enumerate(unit_keys):
            if counts[unit_index] == 0:
                continue                                                       # 当前这个单位已经用完了，跳过

            end_position = position + len(unit)                                # 这个单位放下去以后会占到哪个位置

            if end_position > word_count:
                continue                                                       # 如果超过助记词总长度，就不能放

            crosses_fixed_position = any(
                pos in fixed_positions
                for pos in range(position, end_position)
            )                                                                  # 检查这个词组是否会覆盖固定位置

            if crosses_fixed_position:
                continue                                                       # 不能覆盖固定位置

            next_counts = list(counts)                                         # 拷贝剩余数量
            next_counts[unit_index] -= 1                                       # 当前单位使用一次

            total += count_from(end_position, tuple(next_counts))              # 继续计算后面位置的排列数量

        return total

    return count_from(0, start_counts)                                         # 从第 0 个位置开始计算总数量


def unit_fits(current_words: list, position: int, unit: tuple[str, ...]) -> bool:
    end_position = position + len(unit)                                        # 当前单位会占用的结束位置

    if end_position > len(current_words):
        return False                                                           # 超出助记词长度，不能放

    return all(
        current_words[pos] is None
        for pos in range(position, end_position)
    )                                                                          # 只有这些位置全为空，才可以放这个单位


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
        position += 1                                                          # 跳过已经填好的位置，例如固定位置

    if position == len(current_words):
        yield current_words.copy()                                             # 所有位置都填完，生成一个候选顺序
        return

    for unit in unit_keys:
        if unit_counter[unit] <= 0:
            continue                                                           # 当前单位没有剩余次数，跳过

        if not unit_fits(current_words, position, unit):
            continue                                                           # 当前单位放不下，跳过

        unit_counter[unit] -= 1                                                 # 使用这个单位一次

        for offset, word in enumerate(unit):
            current_words[position + offset] = word                            # 把这个单词或连续词组填入当前位置

        yield from generate_candidate_orders(
            unit_counter,
            unit_keys,
            current_words,
            position + len(unit),
        )                                                                      # 递归生成后面的排列

        for offset in range(len(unit)):
            current_words[position + offset] = None                            # 回溯：撤销刚才填入的词

        unit_counter[unit] += 1                                                 # 回溯：恢复这个单位的剩余次数


def build_receive_context(mnemonic: str, passphrase: str):
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)             # 助记词 + passphrase 生成 seed

    return (
        Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)                         # 用 seed 创建 Bitcoin BIP84 上下文
        .Purpose()                                                             # 路径 m/84'
        .Coin()                                                                # 路径 m/84'/0'
        .Account(0)                                                            # 路径 m/84'/0'/0'
        .Change(Bip44Changes.CHAIN_EXT)                                        # 路径 m/84'/0'/0'/0，外部收款链
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

mnemonic_words = ast.literal_eval(input("Unordered mnemonic word list: ").strip())  # 解析用户输入的 Python 列表

if not isinstance(mnemonic_words, list):
    raise ValueError("Mnemonic words must be provided as a list.")

mnemonic_words = [
    str(word).strip().lower()
    for word in mnemonic_words
]                                                                                  # 统一转成小写，并去掉前后空格

word_count = len(mnemonic_words)                                                   # 助记词数量，通常是 12 或 24

if word_count not in (12, 24):
    raise ValueError(f"This script supports 12 or 24 words. You entered {word_count}.")


words_list = Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH)           # 获取 BIP39 英文词表对象

bip39_words = [
    words_list.GetWordAtIdx(index)
    for index in range(words_list.Length())
]                                                                                  # 转成 Python 列表，里面有 2048 个英文单词

bip39_words_set = set(bip39_words)                                                  # 转成 set，方便快速判断单词是否合法

invalid_words = [
    word
    for word in mnemonic_words
    if word not in bip39_words_set
]                                                                                  # 找出不在 BIP39 词表里的单词

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
fixed_positions = ast.literal_eval(fixed_input) if fixed_input else {}              # 用户不输入时，表示没有固定位置线索

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
adjacent_groups = ast.literal_eval(groups_input) if groups_input else []            # 用户不输入时，表示没有连续词组线索

if not isinstance(adjacent_groups, list):
    raise ValueError("Adjacent groups must be a list.")
print()
passphrase = getpass("BIP39 passphrase, or press Enter if none: ")                  # BIP39 passphrase，没有就直接回车
start_index = int(input("Enter start address index, default 0: ").strip() or "0")   # 起始地址 index，默认 0
address_count = int(input("Enter number of addresses to check, default 20: ").strip() or "20")  # 要检查多少个地址
if start_index < 0:
    raise ValueError("Start index cannot be less than 0.")
if address_count <= 0:
    raise ValueError("Address count must be greater than 0.")
available_words = Counter(mnemonic_words)                                          # 统计每个输入单词出现了几次
template_words = [None] * word_count                                                # 先创建空模板，长度等于助记词数量
fixed_map = {}                                                                      # 保存固定位置，key 是从 0 开始的位置
for position, word in fixed_positions.items():
    position = int(position)                                                        # 用户输入的位置是从 1 开始
    word = str(word).strip().lower()                                                 # 固定位置的单词也统一小写

    if position < 1 or position > word_count:
        raise ValueError(f"Fixed position out of range: {position}")

    if word not in bip39_words_set:
        raise ValueError(f"Fixed word is not a valid BIP39 word: {word}")

    if available_words[word] <= 0:
        raise ValueError(f"Fixed word is not available in the input words: {word}")

    zero_based_position = position - 1                                               # 转成程序内部使用的从 0 开始的位置

    template_words[zero_based_position] = word                                       # 把固定词放进模板
    fixed_map[zero_based_position] = word                                            # 记录这个位置已经固定
    available_words[word] -= 1                                                       # 这个词已经使用掉一次


block_units = []                                                                     # 保存连续词组，每个词组作为一个整体来排列

for group in adjacent_groups:
    if not isinstance(group, list):
        raise ValueError("Each adjacent group must be a list of words.")

    group = [
        str(word).strip().lower()
        for word in group
    ]                                                                                # 清理连续词组里的单词格式

    if len(group) < 2:
        raise ValueError(f"Adjacent group must contain at least 2 words: {group}")

    for word in group:
        if word not in bip39_words_set:
            raise ValueError(f"Group word is not a valid BIP39 word: {word}")

        if available_words[word] <= 0:
            raise ValueError(
                f"Group word is not available after fixed positions are used: {word}"
            )

        available_words[word] -= 1                                                   # 连续词组里的词也算已经使用

    block_units.append(tuple(group))                                                 # 词组转成 tuple，方便作为 Counter 的 key


single_word_units = []                                                               # 剩下的单词，每个都作为单独单位参与排列

for word, count in available_words.items():
    single_word_units.extend([(word,)] * count)                                      # 每个单词也转成 tuple，例如 ("apple",)

unit_counter = Counter(block_units + single_word_units)                              # 统计所有排列单位，包括连续词组和单词
unit_keys = tuple(unit_counter.keys())                                               # 固定单位顺序，递归时会用

total_candidates = count_candidate_orders(
    unit_counter=unit_counter,
    word_count=word_count,
    fixed_map=fixed_map,
)                                                                                    # 精确计算应用线索后需要检查多少种候选顺序

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

benchmark_start = time.time()                                                        # 记录测速开始时间
benchmark_checked = 0                                                                # 测速阶段已经检查的候选数量
benchmark_valid = 0                                                                  # 测速阶段发现的有效 BIP39 助记词数量
benchmark_limit = min(BENCHMARK_LIMIT, total_candidates)                             # 如果总数量小于测速数量，就只测总数量

for candidate_words in generate_candidate_orders(
    unit_counter=unit_counter.copy(),                                                # 用 copy，避免测速消耗掉正式搜索的数据
    unit_keys=unit_keys,
    current_words=template_words.copy(),                                             # 用 copy，避免修改原始模板
    position=0,
):
    benchmark_checked += 1                                                           # 已检查候选数量 +1

    mnemonic = " ".join(candidate_words)                                              # 把候选单词顺序拼成助记词字符串

    if is_valid_mnemonic(mnemonic):
        benchmark_valid += 1                                                         # 当前顺序通过 BIP39 checksum

        receive_ctx = build_receive_context(mnemonic, passphrase)                    # 有效助记词才派生地址

        for address_index in range(start_index, start_index + address_count):
            receive_ctx.AddressIndex(address_index).PublicKey().ToAddress()          # 测速时也模拟真实派生地址成本

    if benchmark_checked >= benchmark_limit:
        break                                                                        # 测速达到指定数量就停止

benchmark_elapsed = max(time.time() - benchmark_start, 0.000001)                     # 避免极端情况下除以 0
speed = benchmark_checked / benchmark_elapsed                                        # 每秒能检查多少候选顺序
estimated_seconds = total_candidates / speed                                         # 根据速度估算总耗时

print(f"Benchmark checked orders : {format_int(benchmark_checked)}")
print(f"Valid BIP39 mnemonics    : {format_int(benchmark_valid)}")
print(f"Estimated speed          : {speed:,.2f} orders/sec")
print(f"Estimated total time     : {format_duration(estimated_seconds)}")
print("=" * 70)
print()

input("Press Enter to start full search, or Ctrl+C to stop now.")


search_start = time.time()                                                           # 正式搜索开始时间
checked_count = 0                                                                    # 正式搜索已检查数量
valid_count = 0                                                                      # 正式搜索中 checksum 有效的助记词数量

for candidate_words in generate_candidate_orders(
    unit_counter=unit_counter,
    unit_keys=unit_keys,
    current_words=template_words.copy(),
    position=0,
):
    checked_count += 1                                                               # 每生成一个候选顺序，计数 +1

    mnemonic = " ".join(candidate_words)                                              # 当前候选顺序转成完整助记词

    if not is_valid_mnemonic(mnemonic):
        if checked_count % PROGRESS_INTERVAL == 0:
            elapsed = max(time.time() - search_start, 0.000001)                      # 已运行时间
            current_speed = checked_count / elapsed                                  # 当前平均速度
            remaining = total_candidates - checked_count                              # 剩余候选数量
            eta = remaining / current_speed                                           # 预计剩余时间

            print(
                f"Checked {checked_count:,} / {total_candidates:,}, "
                f"valid {valid_count:,}, "
                f"speed {current_speed:,.2f}/sec, "
                f"ETA {format_duration(eta)}"
            )
        continue                                                                      # checksum 无效，跳过地址派生
    valid_count += 1                                                                  # checksum 有效的助记词数量 +1
    receive_ctx = build_receive_context(mnemonic, passphrase)                         # 用有效助记词构建 BIP84 派生上下文
    for address_index in range(start_index, start_index + address_count):
        address = receive_ctx.AddressIndex(address_index).PublicKey().ToAddress()     # 派生指定 index 的 bc1q 地址
        if address == target_address:
            path = f"m/84'/0'/0'/0/{address_index}"                                  # 找到匹配地址时，对应的派生路径
            print()
            print("=" * 70)
            print("Match found")
            print("=" * 70)
            print(f"Mnemonic   : {mnemonic}")
            print(f"Passphrase : {passphrase!r}")
            print(f"Path       : {path}")
            print(f"Address    : {address}")
            print("=" * 70)

            raise SystemExit(0)                                                       # 找到后直接退出程序

    if checked_count % PROGRESS_INTERVAL == 0:
        elapsed = max(time.time() - search_start, 0.000001)                          # 已运行时间
        current_speed = checked_count / elapsed                                      # 当前平均速度
        remaining = total_candidates - checked_count                                  # 剩余候选数量
        eta = remaining / current_speed                                               # 预计剩余时间
        print(
            f"Checked {checked_count:,} / {total_candidates:,}, "
            f"valid {valid_count:,}, "
            f"speed {current_speed:,.2f}/sec, "
            f"ETA {format_duration(eta)}"
        )
elapsed = max(time.time() - search_start, 0.000001)                                  # 总运行时间

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
