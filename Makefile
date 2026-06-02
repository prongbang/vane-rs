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
	IPHONEOS_DEPLOYMENT_TARGET=13.0 MACOSX_DEPLOYMENT_TARGET=10.15 cargo swift package --release --accept-all --name VaneSwift --lib-type static
	rm -rf ../VaneSwift/RustFramework.xcframework
	cp -R VaneSwift/RustFramework.xcframework ../VaneSwift/RustFramework.xcframework
	find ../VaneSwift/RustFramework.xcframework -name "libvane.a" -exec xcrun strip -S -x {} \; 2>/dev/null
	rm -rf VaneSwift

build_swift_small:
	IPHONEOS_DEPLOYMENT_TARGET=13.0 MACOSX_DEPLOYMENT_TARGET=10.15 cargo swift package --release --accept-all --name VaneSwift --lib-type static --no-default-features
	rm -rf ../VaneSwift/RustFramework.small.xcframework
	cp -R VaneSwift/RustFramework.xcframework ../VaneSwift/RustFramework.small.xcframework
	find ../VaneSwift/RustFramework.small.xcframework -name "libvane.a" -exec xcrun strip -S -x {} \; 2>/dev/null
	rm -rf VaneSwift

build_kotlin:
	cargo build --release
	cd vane-bindgen && sh generate.sh
	make build_so

build_so:
	rm -rf ../VaneKotlin/library/src/main/jniLibs
	cargo ndk build --release \
	    --target aarch64-linux-android \
        --target armv7-linux-androideabi \
        --target i686-linux-android \
        --target x86_64-linux-android \
        -o ../VaneKotlin/library/src/main/jniLibs
	find ../VaneKotlin/library/src/main/jniLibs -name ".DS_Store" -delete
