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
	IPHONEOS_DEPLOYMENT_TARGET=13.0 cargo swift package --release --accept-all --name VaneSwift
	rm -rf ../VaneSwift/RustFramework.xcframework
	cp -R VaneSwift/RustFramework.xcframework ../VaneSwift/RustFramework.xcframework
	find ../VaneSwift -name "libvane.a" -exec strip -S -x {} \;
	rm -rf VaneSwift

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
        -o ../VaneKotlin/library/src/main/jniLibs
