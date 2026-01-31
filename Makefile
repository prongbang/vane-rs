# setup:
# 	rustup target add \
#         aarch64-apple-ios \
#         x86_64-apple-ios \
#         aarch64-apple-ios-sim
# 	rustup target add \
#         aarch64-linux-android \
#         armv7-linux-androideabi \
#         i686-linux-android \
#         x86_64-linux-android
# 	cargo install cargo-ndk
# 	cargo install cargo-swift
# 	brew install gradle

# new_project:
# 	cargo swift init

# build_swift:
# 	cargo swift package --release
# 	find VaneSwift -name "libvane.a" -exec strip -x {} \;

# build_kotlin:
# 	cargo build --release
# 	cd vane-bindgen && sh generate.sh
# 	make build_so

# build_so:
# 	cargo ndk build --release \
# 	    --target aarch64-linux-android \
#         --target armv7-linux-androideabi \
#         --target i686-linux-android \
#         --target x86_64-linux-android \
#         -o VaneKotlin/library/src/main/jniLibs

TARGET_DIR ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),./target)
BINDINGS_DIR ?= ./output/bindings
KOTLIN_OUT ?= $(BINDINGS_DIR)/kotlin
SWIFT_OUT ?= $(BINDINGS_DIR)/swift
RUNTIME_DYLIB ?= $(TARGET_DIR)/release/libvane.dylib

required:
	cargo install cargo-ndk
	cargo install cargo-swift
	cargo install cargo-bloat

dependency_analysis:
	cargo bloat -p vane --release --lib --crates -- --crate-type=cdylib

test:
	cargo test -p vane

build_android:
	cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 \
	  -o ./output/android \
	  build -p vane --release

build_ios:
	cargo clean
	rm -rf ./output/ios/Vane.xcframework

	RUSTFLAGS="-C link-arg=-dead_strip" cargo build -p vane --release --target aarch64-apple-ios
	RUSTFLAGS="-C link-arg=-dead_strip" cargo build -p vane --release --target aarch64-apple-ios-sim
	#RUSTFLAGS="-C link-arg=-dead_strip" cargo build -p vane --release --target x86_64-apple-ios
	# cargo build -p vane --release --target x86_64-apple-darwin
	# cargo build -p vane --release --target aarch64-apple-darwin

	strip -x $(TARGET_DIR)/aarch64-apple-ios/release/libvane.a
	strip -x $(TARGET_DIR)/aarch64-apple-ios-sim/release/libvane.a
	#strip -x $(TARGET_DIR)/x86_64-apple-ios/release/libvane.a

	# lipo -create \
	#   $(TARGET_DIR)/aarch64-apple-ios-sim/release/libvane.a \
	#   $(TARGET_DIR)/x86_64-apple-ios/release/libvane.a \
	#   -output $(TARGET_DIR)/libvane.a
	lipo -create \
	  $(TARGET_DIR)/aarch64-apple-ios-sim/release/libvane.a \
	  -output $(TARGET_DIR)/libvane.a

	# Verify
	lipo -info $(TARGET_DIR)/libvane.a

	xcodebuild -create-xcframework \
	  -library $(TARGET_DIR)/aarch64-apple-ios/release/libvane.a \
	  -library $(TARGET_DIR)/libvane.a \
	  -output ./output/ios/Vane.xcframework

build_binding:
	cargo build -p vane --release

	mkdir -p $(KOTLIN_OUT) $(SWIFT_OUT)

	# swift
	cargo run -p vane-bindgen --bin uniffi-bindgen -- generate \
	  --language swift \
	  --out-dir $(SWIFT_OUT) \
	  --config ./uniffi.toml \
	  --no-format \
	  --library $(RUNTIME_DYLIB)

	# kotlin
	cargo run -p vane-bindgen --bin uniffi-bindgen -- generate \
	  --language kotlin \
	  --out-dir $(KOTLIN_OUT) \
	  --config ./uniffi.toml \
	  --no-format \
	  --library $(RUNTIME_DYLIB)
