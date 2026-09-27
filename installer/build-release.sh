#!/usr/bin/env bash
# Publie AclMap.exe et AclMap.Collector.exe (fichier unique, runtime .NET 10 Desktop requis) puis construit le MSI.
#   installer/build-release.sh [dossier de sortie]   (défaut : ./release)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/release}"
VERSION="$(grep -oP '(?<=<Version>)[^<]+' "$ROOT/Directory.Build.props")"
STAGE="$(mktemp -d)"
for p in AclMap.UI AclMap.Collector; do
  dotnet publish "$ROOT/src/$p/$p.csproj" -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o "$STAGE/publish" -nologo -v q
done
mkdir -p "$STAGE/msi" "$OUT"
cp "$STAGE/publish/AclMap.exe" "$STAGE/publish/AclMap.Collector.exe" "$ROOT/src/AclMap.UI/Assets/AclMap.ico" "$ROOT/installer/LISEZMOI.txt" "$STAGE/msi/"
"$ROOT/installer/build-msi.sh" "$STAGE/msi" "$VERSION" "$OUT/AclMap-$VERSION.msi"
cp "$ROOT/installer/LISEZMOI.txt" "$OUT/"
( cd "$OUT" && sha256sum "AclMap-$VERSION.msi" > "AclMap-$VERSION.msi.sha256" )
rm -rf "$STAGE"
echo "Version $VERSION -> $OUT"
