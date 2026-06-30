#!/usr/bin/env python3
"""Analyze cold-streak / sterility patterns in a lafleur deep-fuzzer log.

A "stone-cold" child is one whose interestingness score is exactly 0.0 — no new
coverage, timing, or JIT-vitals signal, so there is no gradient for the
evolutionary loop to climb. lafleur retires such parents early once their
consecutive-zero-score streak exceeds ``COLD_STERILITY_LIMIT`` (see
``lafleur/orchestrator.py``). This tool reconstructs, per parent file, the stream
of child outcomes from a run log and answers:

  1. How often does a run of consecutive 0.0-score children end in a find
     (interesting child) vs a warm near-miss vs the parent being abandoned?
  2. When a find happens, how many consecutive 0.0 children immediately
     preceded it (the "cold streak before a find")?
  3. If we retired parents early at ``COLD_STERILITY_LIMIT = K`` consecutive cold
     children, how many finds would we lose and how many wasted child
     executions would we save? Replayed across several K so the threshold can be
     re-tuned against real runs.

Outcomes are driven off the per-run score lines the orchestrator prints:
  "[+] Child IS NOT interesting with score: S"  -> COLD (S<=0) or WARM (S>0)
  "[***] SUCCESS! Mutation #N found new coverage" -> FIND  (resets streak)
  "... known duplicate behavior ..." / "Discarding to prevent" -> DUP (neutral)
The current parent is taken from "\\-> Running mutation #N (Seed: S) for X.py".

Usage:
  python scripts/analyze_cold_streaks.py path/to/deep_fuzzer_run_*.log
  python scripts/analyze_cold_streaks.py run.log --limits 50 100 250 599
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

# --- Line patterns -----------------------------------------------------------
RE_RUNNING = re.compile(r"Running mutation #(\d+) \(Seed: \d+\) for (\S+?\.py)")
# Score may be negative (the density penalty can drive it below 0). Per the
# implementation, only score > 0.0 is "warm"; 0.0 and negatives are stone-cold.
RE_NOT_INTERESTING = re.compile(r"Child IS NOT interesting with score: (-?[\d.]+)")
RE_SUCCESS = re.compile(r"SUCCESS! Mutation #\d+ found new coverage")
RE_DUPLICATE = re.compile(r"known duplicate behavior|Discarding to prevent")

# Default early-retirement thresholds to simulate.
DEFAULT_LIMITS = [50, 100, 250, 599]


@dataclass
class ParentState:
    """Running per-parent bookkeeping during the replay."""

    streak: int = 0  # current consecutive-cold streak
    cold: int = 0
    warm: int = 0
    finds: int = 0
    dups: int = 0
    max_streak: int = 0
    # streak length immediately before each find (the cold run a find broke)
    streak_before_find: list[int] = field(default_factory=list)


def parse(path: str) -> dict:
    """Replay a run log into per-parent outcome streams and tallies."""
    parents: dict[str, ParentState] = defaultdict(ParentState)
    cur: str | None = None

    # Ordered stream of (parent, outcome) for the retirement simulation.
    stream: list[tuple[str, str]] = []

    # Streak-termination tally: what broke each cold run (length > 0 only).
    terminations: Counter[str] = Counter()  # find / warm / abandoned
    find_streaks: list[int] = []  # streak_before for every find

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = RE_RUNNING.search(line)
            if m:
                cur = m.group(2)
                continue
            if cur is None:
                continue

            m = RE_NOT_INTERESTING.search(line)
            if m:
                score = float(m.group(1))
                st = parents[cur]
                if score > 0.0:
                    st.warm += 1
                    if st.streak > 0:
                        terminations["warm"] += 1
                    st.streak = 0
                    stream.append((cur, "warm"))
                else:
                    st.cold += 1
                    st.streak += 1
                    st.max_streak = max(st.max_streak, st.streak)
                    stream.append((cur, "cold"))
                continue

            # The bare "is interesting" line is informational; the following
            # SUCCESS (kept) or DUP (rejected) line resolves the real outcome.
            if RE_SUCCESS.search(line):
                st = parents[cur]
                st.finds += 1
                st.streak_before_find.append(st.streak)
                find_streaks.append(st.streak)
                if st.streak > 0:
                    terminations["find"] += 1
                st.streak = 0
                stream.append((cur, "find"))
                continue

            if RE_DUPLICATE.search(line):
                parents[cur].dups += 1
                stream.append((cur, "dup"))  # neutral: does not touch streak
                continue

    # Any parent left with streak > 0 ended cold without a find/warm = abandoned.
    abandoned_residual = [st.streak for st in parents.values() if st.streak > 0]
    terminations["abandoned"] = len(abandoned_residual)

    return {
        "parents": parents,
        "stream": stream,
        "terminations": terminations,
        "find_streaks": find_streaks,
        "abandoned_residual": abandoned_residual,
    }


def simulate_retirement(stream: list[tuple[str, str]], limit: int) -> dict:
    """Replay the outcome stream under an early-retirement policy.

    Once a parent's consecutive-cold streak exceeds ``limit`` the parent is
    retired and every subsequent child attributed to it would not have run.
    """
    streak: dict[str, int] = defaultdict(int)
    retired: set[str] = set()
    lost_finds = 0
    skipped_children = 0
    for parent, outcome in stream:
        if parent in retired:
            skipped_children += 1
            if outcome == "find":
                lost_finds += 1
            continue
        if outcome == "cold":
            streak[parent] += 1
            if streak[parent] > limit:
                retired.add(parent)
        elif outcome in ("warm", "find"):
            streak[parent] = 0
        # dup: neutral
    return {
        "limit": limit,
        "lost_finds": lost_finds,
        "skipped_children": skipped_children,
        "retired_parents": len(retired),
    }


def histogram(values: list[int], buckets: list[tuple[int, int]]) -> list[tuple[str, int]]:
    """Bucket ``values`` into inclusive [lo, hi] ranges and count each."""
    out = []
    for lo, hi in buckets:
        label = f"{lo}" if lo == hi else (f"{lo}+" if hi == 1 << 30 else f"{lo}-{hi}")
        n = sum(1 for v in values if lo <= v <= hi)
        out.append((label, n))
    return out


def report(path: str, limits: list[int]) -> None:
    """Parse the log at ``path`` and print the full cold-streak report."""
    r = parse(path)
    parents = r["parents"]
    stream = r["stream"]

    total_children = sum(1 for _, o in stream if o in ("cold", "warm", "find", "dup"))
    if total_children == 0:
        print(f"No scored children found in {path}. Is this a deep_fuzzer run log?")
        return
    total_cold = sum(st.cold for st in parents.values())
    total_warm = sum(st.warm for st in parents.values())
    total_finds = sum(st.finds for st in parents.values())
    total_dups = sum(st.dups for st in parents.values())
    find_streaks = r["find_streaks"]

    print("=" * 72)
    print("COLD-STREAK / STERILITY ANALYSIS")
    print(f"log: {path}")
    print("=" * 72)
    print(f"\nParents seen (mutated):        {len(parents):>8}")
    print(f"Total child executions:        {total_children:>8}")
    print(
        f"  stone-cold (score <= 0):     {total_cold:>8}  "
        f"({100 * total_cold / total_children:5.1f}%)"
    )
    print(
        f"  warm near-miss (0<s<10):     {total_warm:>8}  "
        f"({100 * total_warm / total_children:5.1f}%)"
    )
    print(
        f"  finds (interesting->kept):   {total_finds:>8}  "
        f"({100 * total_finds / total_children:5.1f}%)"
    )
    print(
        f"  duplicate/discard (neutral): {total_dups:>8}  "
        f"({100 * total_dups / total_children:5.1f}%)"
    )

    # --- Q1: what terminates a cold run? -------------------------------------
    print("\n" + "-" * 72)
    print("Q1. What ends a run of consecutive stone-cold children?")
    print("    (only counting cold runs of length >= 1)")
    t = r["terminations"]
    ended = t["find"] + t["warm"] + t["abandoned"]
    if ended:
        print(
            f"  ended by a FIND (interesting):   {t['find']:>6}  ({100 * t['find'] / ended:5.1f}%)"
        )
        print(
            f"  ended by a WARM near-miss:       {t['warm']:>6}  ({100 * t['warm'] / ended:5.1f}%)"
        )
        print(
            f"  never ended (parent abandoned):  {t['abandoned']:>6}  "
            f"({100 * t['abandoned'] / ended:5.1f}%)"
        )

    # --- Q2: cold streak immediately before a find --------------------------
    print("\n" + "-" * 72)
    print("Q2. Cold streak immediately preceding each find")
    finds_with_cold = sum(1 for s in find_streaks if s >= 1)
    print(f"  total finds:                         {len(find_streaks):>6}")
    print(
        f"  finds with NO cold lead-in (s=0):    {len(find_streaks) - finds_with_cold:>6}  "
        f"({100 * (len(find_streaks) - finds_with_cold) / max(1, len(find_streaks)):5.1f}%)"
    )
    print(
        f"  finds preceded by >=1 cold child:    {finds_with_cold:>6}  "
        f"({100 * finds_with_cold / max(1, len(find_streaks)):5.1f}%)"
    )
    if find_streaks:
        srt = sorted(find_streaks)
        print(f"  preceding-cold-streak max:           {max(find_streaks):>6}")
        print(
            f"  preceding-cold-streak mean:          {sum(find_streaks) / len(find_streaks):>6.1f}"
        )
        print(f"  preceding-cold-streak median:        {srt[len(srt) // 2]:>6}")
        print(f"  preceding-cold-streak p90:           {srt[int(0.9 * (len(srt) - 1))]:>6}")
        print(f"  preceding-cold-streak p99:           {srt[int(0.99 * (len(srt) - 1))]:>6}")
        print("  histogram of cold streak before a find:")
        buckets = [(0, 0), (1, 4), (5, 9), (10, 24), (25, 49), (50, 99), (100, 249), (250, 1 << 30)]
        for label, n in histogram(find_streaks, buckets):
            bar = "#" * int(60 * n / max(1, len(find_streaks)))
            print(f"    {label:>8} cold -> find : {n:>5}  {bar}")

    # --- Q3: longest cold comebacks -----------------------------------------
    print("\n" + "-" * 72)
    print("Q3. Longest cold streaks that STILL produced a find (comebacks)")
    comebacks = sorted(
        ((s, p) for p, st in parents.items() for s in st.streak_before_find if s >= 50),
        reverse=True,
    )
    if comebacks:
        for s, p in comebacks[:15]:
            print(f"  {s:>5} consecutive cold children, then a find  ({p})")
    else:
        print("  (no find was ever preceded by a cold streak >= 50)")

    # --- Q4: retirement-policy simulation -----------------------------------
    print("\n" + "-" * 72)
    print("Q4. Early-retirement simulation (retire after K consecutive cold children)")
    print(f"  baseline (no early retirement): {total_finds} finds, {total_children} child execs")
    print(
        f"  {'K':>5} | {'finds lost':>10} | {'% finds lost':>12} | "
        f"{'child execs saved':>17} | {'% saved':>8} | {'parents retired':>15}"
    )
    for limit in limits:
        sim = simulate_retirement(stream, limit)
        pct_lost = 100 * sim["lost_finds"] / max(1, total_finds)
        pct_saved = 100 * sim["skipped_children"] / max(1, total_children)
        print(
            f"  {limit:>5} | {sim['lost_finds']:>10} | {pct_lost:>11.2f}% | "
            f"{sim['skipped_children']:>17} | {pct_saved:>7.2f}% | {sim['retired_parents']:>15}"
        )

    # --- Q5: per-parent productivity vs coldness ----------------------------
    print("\n" + "-" * 72)
    print("Q5. Per-parent coldness vs productivity")
    never_found = [p for p, st in parents.items() if st.finds == 0]
    cold_only = [p for p, st in parents.items() if st.finds == 0 and st.warm == 0 and st.cold > 0]
    print(f"  parents that NEVER produced a find:          {len(never_found):>5} / {len(parents)}")
    print(f"  parents that only ever went cold (no warm):  {len(cold_only):>5}")
    big_cold_no_find = [
        (st.max_streak, p) for p, st in parents.items() if st.finds == 0 and st.max_streak >= 100
    ]
    print(
        f"  parents with max cold streak >=100 and 0 finds: {len(big_cold_no_find):>4}  "
        "(correctly retired by COLD_STERILITY_LIMIT=100)"
    )
    abandoned = r["abandoned_residual"]
    if abandoned:
        print(
            f"  parents abandoned mid-cold-streak: {len(abandoned)} "
            f"(residual streak max={max(abandoned)}, sum wasted tail={sum(abandoned)})"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze cold-streak / sterility patterns in a lafleur deep-fuzzer log."
    )
    parser.add_argument("log", help="Path to a deep_fuzzer_run_*.log file")
    parser.add_argument(
        "--limits",
        type=int,
        nargs="+",
        default=DEFAULT_LIMITS,
        help="COLD_STERILITY_LIMIT values to simulate (default: 50 100 250 599)",
    )
    args = parser.parse_args()
    report(args.log, args.limits)


if __name__ == "__main__":
    main()
