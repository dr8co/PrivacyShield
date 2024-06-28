#!/usr/bin/env bash

# This script is used to search for files or directories that match a pattern.
# It searches recursively and returns the first match found.

# Check if exactly one argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <pattern>"
    exit 1
fi

pattern=$1

# Find files or directories that match the pattern and store them in an array
IFS=$'\n' read -d '' -r -a matches < <(find $(dirname "$pattern") -name "$(basename "$pattern")" | sort -r 2>/dev/null)

# Check if any matches were found
if [ ${#matches[@]} -eq 0 ]; then
    echo "No matches found."
    exit 1
else
  # Print the first match
  echo "${matches[0]}"
fi
