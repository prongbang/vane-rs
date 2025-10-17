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

new_project:
	cargo swift init

build_spm:
	cargo swift package --release
