#!/usr/bin/env python3

import sys
import glob


def search_filesystem(pattern: str) -> None:
    """
    Search the filesystem for files or directories that match the pattern
    :param pattern: The pattern to search for
    :return: None
    """
    # Find files or directories that match the pattern
    matches = glob.glob(pattern, recursive=True)

    # Check if there are any matches
    if not matches:
        print(f"No matches found for pattern: {pattern}")
    else:
        # Sort matches in reverse order
        matches.sort(reverse=True)

        # Select the first match (after sorting in reverse order)
        print(matches[0])


if __name__ == "__main__":
    # Check if exactly one argument is provided
    if len(sys.argv) != 2:
        print("Usage: python3 search.py <pattern>")
        sys.exit(1)

    search_filesystem(sys.argv[1])
