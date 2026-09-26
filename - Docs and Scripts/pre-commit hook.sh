#!/bin/sh
# A pre-commit hook; wire it up if you want to edit GenericConsole.cpp directly,
# and not edit the WindowsUTF8Console.cpp, WindowsWideConsole.cpp, or LinuxConsole.cpp
# files when customizing the project.
#
# Requires Bash 3.2 or newer. This deliberately avoids Perl, sed-specific
# extensions, associative arrays, mapfile, and other Bash 4+ features.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
if git -C "$repo" diff --cached --quiet -- GenericConsole.cpp; then
  exit 0
fi

bash "$repo/- Docs and Scripts/GenerateConsoleSources.sh"
git -C "$repo" add -- WindowsUTF8Console.cpp LinuxConsole.cpp WindowsWideConsole.cpp
