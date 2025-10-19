cargo run \
    --bin uniffi-bindgen generate \
    --library ../VaneKotlin/library/src/main/jniLibs/arm64-v8a/libvane.so \
    --language kotlin \
    --out-dir ../VaneKotlin/library/src/main/java/ \
    --no-format
    # for desktop
    # --library ~/.cargo-target/release/libvane.dylib \
mv ../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/vane.kt ../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/Vane.kt
