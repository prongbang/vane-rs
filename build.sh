#!/usr/bin/env bash
set -e

# Build & bind iOS
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
cargo run --bin uniffi-bindgen generate --language swift --out-dir bindings/ios target/release/libvane.a

# Build & bind Android
cargo ndk --target aarch64-linux-android \
          --target armv7-linux-androideabi \
          --target i686-linux-android \
          --target x86_64-linux-android \
          --platform 21 \
          --release build
cargo run --bin uniffi-bindgen generate --language kotlin --out-dir bindings/android target/release/libvane.so
