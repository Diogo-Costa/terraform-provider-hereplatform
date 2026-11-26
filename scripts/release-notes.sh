#!/usr/bin/env bash
# Prints the CHANGELOG.md section of a version without its heading: the notes of its GitHub release.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <version> [changelog]" >&2
  exit 2
fi

version="${1#v}"
changelog="${2:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md}"

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "error: '$1' is not a version of the form vX.Y.Z" >&2
  exit 1
fi
if [[ ! -f "$changelog" ]]; then
  echo "error: $changelog not found" >&2
  exit 1
fi

# POSIX awk only: no interval expressions or gawk extensions, so mawk on the runners behaves the same.
awk -v v="$version" -v file="$changelog" '
  { sub(/\r$/, "") }
  /^[ \t]*(```|~~~)/ { fence = !fence }
  !fence && /^##?[ \t]/ {
    section = 0
    if ($1 == "##" && $2 == v) {
      found++
      heading = $0
      section = 1
      next
    }
  }
  section { body[++n] = $0 }
  END {
    if (found == 0) { err = sprintf("%s has no \"## %s\" section", file, v) }
    else if (found > 1) { err = sprintf("%s has %d \"## %s\" sections", file, found, v) }
    else if (tolower(heading) ~ /unreleased/) { err = sprintf("%s marks %s as unreleased: %s", file, v, heading) }
    if (err == "") {
      first = 1
      while (first <= n && body[first] ~ /^[ \t]*$/) first++
      last = n
      while (last >= first && body[last] ~ /^[ \t]*$/) last--
      if (first > last) { err = sprintf("the \"## %s\" section of %s is empty", v, file) }
    }
    if (err != "") { print "error: " err > "/dev/stderr"; exit 1 }
    for (i = first; i <= last; i++) print body[i]
  }
' "$changelog"
