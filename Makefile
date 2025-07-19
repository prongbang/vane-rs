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

build:
	# Build for iOS
	cargo build --release --target aarch64-apple-ios
	cargo build --release --target x86_64-apple-ios

	# Build for Android
	cargo build --release --target aarch64-linux-android
	cargo build --release --target armv7-linux-androideabi
	cargo build --release --target i686-linux-android
	cargo build --release --target x86_64-linux-android

	# Generate bindings
	cargo run --bin uniffi-bindgen generate src/vane.udl --language swift --out-dir VaneSwift/Sources/VaneSwift/
	cargo run --bin uniffi-bindgen generate src/vane.udl --language kotlin --out-dir VaneKt/src/main/java/ --no-format
	mv VaneKt/src/main/java/com/inteniquetic/vane/vane.kt VaneKt/src/main/java/com/inteniquetic/vane/Vane.kt
