setup:
	rustup target add \
        aarch64-apple-ios \
        x86_64-apple-ios \
        aarch64-apple-ios-sim
	rustup target add \
        aarch64-linux-android \
        armv7-linux-androideabi \
        i686-linux-android \
        x86_64-linux-android
	cargo install cargo-ndk
	cargo install cargo-swift
	brew install gradle

new_project:
	cargo swift init

build_swift:
	cargo swift package --release
	find VaneSwift -name "libvane.a" -exec strip -x {} \;

build_kotlin:
	cargo build --release
	cd vane-bindgen && sh generate.sh
	make build_so

build_so:
	cargo ndk build --release \
	    --target aarch64-linux-android \
        --target armv7-linux-androideabi \
        --target i686-linux-android \
        --target x86_64-linux-android \
        -o VaneKotlin/library/src/main/jniLibs
