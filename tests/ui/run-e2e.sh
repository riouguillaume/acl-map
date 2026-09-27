#!/usr/bin/env bash
# Lance deux hôtes de développement neufs (5180 : domaine configuré, 5181 : poste neuf) puis les tests Playwright.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DLL="$ROOT/tools/AclMap.DevHost/bin/Debug/net10.0/AclMap.DevHost.dll"
pids=()
for p in 5180 5181; do
  pre=configured; [ "$p" = 5181 ] && pre=empty
  dotnet "$DLL" --port "$p" --preset "$pre" --viewer "$ROOT/src/AclMap.UI/Assets/Viewer" > "/tmp/devhost-$p.log" 2>&1 & pids+=($!)
done
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT
sleep 4
node "$(dirname "$0")/e2e.mjs"
