setup:
	rustup target add \
        aarch64-apple-ios \
        x86_64-apple-ios \
        aarch64-apple-ios-sim
	rustup target add \
        aarch64-linux-android \
        armv7-linux-androideabi \
        x86_64-linux-android
	cargo install cargo-ndk
	cargo install cargo-swift --version "^0.11"
	brew install gradle

new_project:
	cargo swift init

# cargo-swift >= 0.11 is required: 0.9 bundles uniffi 0.29, whose metadata
# reader is one byte out of step with 0.31's record-field defaults (it reads the
# literal kind where 0.31 writes a DefaultValue discriminator first) and fails
# with "invalid utf-8" on _UNIFFI_META_VANE_RECORD_VANERESPONSE. It also names
# the bundle after the FFI module now, hence the explicit --xcframework-name.
build_swift:
	IPHONEOS_DEPLOYMENT_TARGET=13.0 MACOSX_DEPLOYMENT_TARGET=10.15 cargo swift package --release --accept-all --name VaneSwift --xcframework-name RustFramework --lib-type static
	rm -rf ../VaneSwift/RustFramework.xcframework
	cp -R VaneSwift/RustFramework.xcframework ../VaneSwift/RustFramework.xcframework
	find ../VaneSwift/RustFramework.xcframework -name "libvane.a" -exec xcrun strip -S -x {} \; 2>/dev/null
	$(MAKE) strip_swift_archives XCFRAMEWORK=../VaneSwift/RustFramework.xcframework
	rm -rf VaneSwift

build_swift_small:
	IPHONEOS_DEPLOYMENT_TARGET=13.0 MACOSX_DEPLOYMENT_TARGET=10.15 cargo swift package --release --accept-all --name VaneSwift --xcframework-name RustFramework --lib-type static --no-default-features
	rm -rf ../VaneSwift/RustFramework.small.xcframework
	cp -R VaneSwift/RustFramework.xcframework ../VaneSwift/RustFramework.small.xcframework
	find ../VaneSwift/RustFramework.small.xcframework -name "libvane.a" -exec xcrun strip -S -x {} \; 2>/dev/null
	$(MAKE) strip_swift_archives XCFRAMEWORK=../VaneSwift/RustFramework.small.xcframework
	rm -rf VaneSwift

strip_swift_archives:
	bash scripts/strip-swift-archives.sh "$(XCFRAMEWORK)"

build_kotlin:
	cargo build --release
	cd vane-bindgen && sh generate.sh
	make build_so

# 32-bit x86 is dropped: Android 12+ system images are 64-bit only and Google
# no longer ships 32-bit x86 emulator images, so it cost ~5.8 MB uncompressed
# for no reachable consumer. x86_64 stays — dropping it would break
# System.loadLibrary at runtime on Intel-host emulators, most cloud CI, and
# ChromeOS, which runs Android apps on x86_64 natively.
build_so:
	rm -rf ../VaneKotlin/library/src/main/jniLibs
	cargo ndk build --release \
	    --target aarch64-linux-android \
        --target armv7-linux-androideabi \
        --target x86_64-linux-android \
        -o ../VaneKotlin/library/src/main/jniLibs
	find ../VaneKotlin/library/src/main/jniLibs -name ".DS_Store" -delete
# quiche declares crate-type = ["lib", "staticlib", "cdylib"], so Cargo emits a
# libquiche-<hash>.so byproduct that cargo-ndk copies alongside ours. Nothing
# loads it: vane links quiche's rlib statically, libvane.so carries no NEEDED
# entry for it, and the only System.loadLibrary/Native.register call names
# "vane". Shipping it added ~659 KB of dead weight across the ABI set.
	find ../VaneKotlin/library/src/main/jniLibs -name 'libquiche-*.so' -delete
	$(MAKE) check_so_links

# A cdylib link tolerates undefined symbols, so a libvane.so that is missing
# every BoringSSL symbol still "builds" — and then fails at System.loadLibrary
# on every device. That shipped twice in one day: a poisoned boring-sys
# CMakeCache in a cargo target dir (left by some non-cargo-ndk build) makes
# later rebuilds silently reuse a host-arch Mach-O archive, whose members lld
# skips. Nothing downstream notices: unit tests never load the .so and the CI
# staleness gate only diffs bytes. If this fires, purge
# `release/build/boring-sys-*` and `release/.fingerprint/boring-sys-*` for the
# Android targets in EVERY cargo target dir, then rebuild.
check_so_links:
	@nm=$$(ls "$$HOME/Library/Android/sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/"*/bin/llvm-nm 2>/dev/null | head -1); \
	if [ -z "$$nm" ]; then echo "check_so_links: llvm-nm not found, SKIPPED" >&2; exit 0; fi; \
	fail=0; \
	for so in ../VaneKotlin/library/src/main/jniLibs/*/libvane.so; do \
	    n=$$("$$nm" -D --undefined-only "$$so" | grep -cE ' U (SSL_|EVP_|CRYPTO_|X509_)' || true); \
	    if [ "$$n" -ne 0 ]; then echo "check_so_links: $$so has $$n undefined BoringSSL symbols — it cannot dlopen" >&2; fail=1; \
	    else echo "check_so_links: $$so ok"; fi; \
	done; \
	exit $$fail

# This machine hit ENOSPC twice with target/ at ~10 GB. Run when low on disk or
# after a toolchain bump (old rustc caches never get evicted on their own).
# Cost: the next build is a cold build, minutes not seconds — that is the whole
# trade. cargo clean keeps nothing, so there is no partial variant worth having.
clean:
	cargo clean
	cd vane-bindgen && cargo clean
