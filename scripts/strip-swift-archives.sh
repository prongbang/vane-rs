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
        # Strip per object, not per archive. `strip` on a .a rewrites the
        # archive and stamps __.SYMDEF with the current time on every run --
        # measured: two `strip` invocations on one unchanged file eight seconds
        # apart produced two different SHA-1s. Doing it here leaves the
        # `libtool -D` below as the last thing to touch the archive, which is
        # what makes the output reproducible.
        xcrun strip -S -x "$obj" 2>/dev/null || true
    done

    # -D is load-bearing, not tidiness. Without it libtool stamps each ar
    # member header with the current time, so two builds of byte-identical
    # object code produce different archives -- and these archives are tracked
    # in git under a `git diff --exit-code` gate, which then fails on every
    # rebuild forever. Verified: with the stamps, two runs from the same commit
    # on the same machine differ; extracting both gives 912 members with not
    # one byte of content between them. Same reason the Info.plist sort below
    # exists.
    libtool -D -static -o "$output" "$tmp"/objects/*.o >/dev/null 2>/dev/null
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
