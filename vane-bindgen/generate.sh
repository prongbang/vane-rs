cargo run \
    --bin uniffi-bindgen generate \
    --library ~/.cargo-target/release/libvane.dylib \
    --language kotlin \
    --out-dir ../VaneKotlin/src/main/java/ \
    --no-format
mv ../VaneKotlin/src/main/java/com/inteniquetic/vanekotlin/vane.kt ../VaneKotlin/src/main/java/com/inteniquetic/vanekotlin/Vane.kt
