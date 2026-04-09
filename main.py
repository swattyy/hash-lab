#!/usr/bin/env python3
"""
hash-lab: Educational hash analysis and dictionary attack tool.
For CTF challenges and authorized security testing only.
"""

import argparse
import hashlib
import re
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()

HASH_TYPES: dict[str, dict] = {
    "MD5":    {"length": 32, "pattern": r"^[a-fA-F0-9]{32}$"},
    "SHA1":   {"length": 40, "pattern": r"^[a-fA-F0-9]{40}$"},
    "SHA256": {"length": 64, "pattern": r"^[a-fA-F0-9]{64}$"},
    "SHA512": {"length": 128, "pattern": r"^[a-fA-F0-9]{128}$"},
    "NTLM":   {"length": 32, "pattern": r"^[a-fA-F0-9]{32}$"},
    "bcrypt": {"length": 60, "pattern": r"^\$2[aby]?\$\d{2}\$.{53}$"},
}

LEET_MAP: dict[str, str] = {"a": "@", "e": "3", "s": "$", "o": "0"}
ALGO_MAP: dict[str, str] = {"MD5": "md5", "SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}


def identify_hash(hash_str: str) -> list[str]:
    """Identify possible hash types based on length and format."""
    return [name for name, info in HASH_TYPES.items() if re.match(info["pattern"], hash_str)]


def hash_string(plaintext: str, algorithm: str) -> str:
    """Hash a plaintext string with the given algorithm."""
    algo = algorithm.upper()
    if algo == "NTLM":
        return hashlib.new("md4", plaintext.encode("utf-16le")).hexdigest()
    if algo == "BCRYPT":
        console.print("[red]bcrypt hashing requires the bcrypt library (not included).[/red]")
        sys.exit(1)
    if algo not in ALGO_MAP:
        console.print(f"[red]Unsupported algorithm: {algorithm}[/red]")
        sys.exit(1)
    return hashlib.new(ALGO_MAP[algo], plaintext.encode()).hexdigest()


def generate_mutations(word: str) -> list[str]:
    """Generate common mutations of a word for dictionary attacks."""
    mutations: list[str] = [word, word.capitalize(), word.upper()]
    # Append numbers 0-99
    for n in range(100):
        mutations.append(f"{word}{n}")
        mutations.append(f"{word.capitalize()}{n}")
    # Leet speak
    leet = word
    for original, replacement in LEET_MAP.items():
        leet = leet.replace(original, replacement)
    if leet != word:
        mutations.append(leet)
    # Common suffixes
    for suffix in ["!", "!!", "123", "@", "#", "$"]:
        mutations.append(f"{word}{suffix}")
        mutations.append(f"{word.capitalize()}{suffix}")
    return mutations


def crack_hash(target_hash: str, wordlist_path: str, algorithm: str) -> None:
    """Attempt to crack a hash using a wordlist with mutations."""
    path = Path(wordlist_path)
    if not path.exists():
        console.print(f"[red]Wordlist not found: {wordlist_path}[/red]")
        sys.exit(1)

    words = [w.strip() for w in path.read_text(encoding="utf-8", errors="ignore").splitlines() if w.strip()]

    console.print(f"\n[bold cyan]Target hash:[/bold cyan]  {target_hash}")
    console.print(f"[bold cyan]Algorithm:[/bold cyan]    {algorithm}")
    console.print(f"[bold cyan]Wordlist:[/bold cyan]     {wordlist_path} ({len(words)} words)")
    console.print(f"[bold cyan]Mutations:[/bold cyan]    enabled (numbers, capitalize, leet, suffixes)\n")

    attempts = 0
    start_time = time.time()

    for word in words:
        for candidate in generate_mutations(word):
            attempts += 1
            candidate_hash = hash_string(candidate, algorithm)

            if attempts % 5000 == 0:
                console.print(f"  [dim]Tried {attempts:,} candidates...[/dim]", end="\r")

            if candidate_hash == target_hash.lower():
                elapsed = time.time() - start_time
                console.print(f"\n[bold green]CRACKED![/bold green]")
                table = Table(title="Result", show_header=False)
                table.add_column("Field", style="cyan")
                table.add_column("Value", style="white")
                table.add_row("Plaintext", candidate)
                table.add_row("Hash", candidate_hash)
                table.add_row("Algorithm", algorithm)
                table.add_row("Attempts", f"{attempts:,}")
                table.add_row("Time", f"{elapsed:.2f}s")
                console.print(table)
                return

    elapsed = time.time() - start_time
    console.print(f"\n[bold red]NOT FOUND[/bold red] after {attempts:,} attempts in {elapsed:.2f}s")
    console.print("[dim]Try a larger wordlist or different algorithm.[/dim]")


def show_hash_info(hash_str: str) -> list[str]:
    """Display information about a hash string."""
    possible = identify_hash(hash_str)
    table = Table(title="Hash Analysis")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Input", hash_str)
    table.add_row("Length", str(len(hash_str)))
    table.add_row("Possible types", ", ".join(possible) if possible else "Unknown")
    console.print(table)
    return possible


def main() -> None:
    parser = argparse.ArgumentParser(
        description="hash-lab: Educational hash analysis and dictionary attack tool",
        epilog="For CTF challenges and authorized security testing only.",
    )
    parser.add_argument("input", help="Hash to analyze/crack, or plaintext to hash")
    parser.add_argument("--wordlist", "-w", help="Path to wordlist file for dictionary attack")
    parser.add_argument("--hash", action="store_true", help="Hash the input plaintext instead of cracking")
    parser.add_argument(
        "--algorithm", "-a",
        choices=["md5", "sha1", "sha256", "sha512", "ntlm"],
        default="md5",
        help="Hash algorithm (default: md5)",
    )
    args = parser.parse_args()

    console.print("[bold magenta]hash-lab[/bold magenta] [dim]v1.0[/dim]\n")

    # Mode: hash a plaintext string
    if args.hash:
        algo = args.algorithm.upper()
        result = hash_string(args.input, algo)
        table = Table(title="Hashing Result", show_header=False)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Plaintext", args.input)
        table.add_row("Algorithm", algo)
        table.add_row("Hash", result)
        console.print(table)
        return

    # Mode: analyze or crack a hash
    possible = show_hash_info(args.input)

    if args.wordlist:
        if not possible:
            console.print("[red]Cannot determine hash type. Use --algorithm to specify.[/red]")
            sys.exit(1)
        algo = args.algorithm.upper()
        if algo == "MD5" and "MD5" not in possible and len(possible) == 1:
            algo = possible[0]
        crack_hash(args.input, args.wordlist, algo)
    else:
        console.print("\n[dim]Tip: Use --wordlist to attempt a dictionary attack.[/dim]")


if __name__ == "__main__":
    main()
