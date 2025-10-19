cargo run \
    --bin uniffi-bindgen generate \
    --library src/vane.udl \
    --language kotlin \
    --out-dir ../VaneKotlin/library/src/main/java/ \
    --no-format
    # for desktop
    # --library ~/.cargo-target/release/libvane.dylib \
mv ../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/vane.kt ../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/Vane.kt
