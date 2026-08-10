#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <RustFramework.xcframework>" >&2
    exit 2
fi

xcframework="$1"
bitcode_strip="$(xcrun -find bitcode_strip)"

strip_thin_archive() {
    local input="$1"
    local output="$2"
    local tmp
    tmp="$(mktemp -d)"
    mkdir -p "$tmp/objects"

    (cd "$tmp/objects" && ar -x "$input")
    for obj in "$tmp"/objects/*.o; do
        "$bitcode_strip" "$obj" -r -o "$obj.stripped" >/dev/null 2>&1 && mv "$obj.stripped" "$obj" || true
    done

    libtool -static -o "$output" "$tmp"/objects/*.o >/dev/null 2>/dev/null
    xcrun strip -S -x "$output" 2>/dev/null || true
    rm -rf "$tmp"
}

while IFS= read -r archive; do
    archive="$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")"
    tmp="$(mktemp -d)"
    info="$(lipo -info "$archive")"

    if [[ "$info" == Architectures\ in\ the\ fat\ file:* ]]; then
        archs="${info##*: }"
        outputs=()
        for arch in $archs; do
            thin="$tmp/$arch.a"
            stripped="$tmp/$arch.stripped.a"
            lipo "$archive" -thin "$arch" -output "$thin"
            strip_thin_archive "$thin" "$stripped"
            outputs+=("$stripped")
        done
        lipo -create "${outputs[@]}" -output "$archive"
    else
        strip_thin_archive "$archive" "$tmp/libvane.a"
        mv "$tmp/libvane.a" "$archive"
    fi

    rm -rf "$tmp"
done < <(find "$xcframework" -name "libvane.a")

# cargo-swift emits AvailableLibraries in an arbitrary order — two runs from the
# same source produced ios/ios-sim/macos and macos/ios/ios-sim. The content is
# identical either way, but the XCFrameworks are tracked in git and the release
# workflow gates on `git diff --exit-code -- VaneSwift`, so an unsorted array
# fails a release with a diff nobody can act on. Sort by slice identifier.
python3 - "$xcframework/Info.plist" <<'PY'
import plistlib
import sys

path = sys.argv[1]
with open(path, "rb") as handle:
    plist = plistlib.load(handle)
plist["AvailableLibraries"].sort(key=lambda library: library["LibraryIdentifier"])
with open(path, "wb") as handle:
    plistlib.dump(plist, handle)
PY
