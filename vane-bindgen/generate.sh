cargo run \
    --bin uniffi-bindgen generate ~/.cargo-target/release/libvane.dylib \
    --library \
    --language kotlin \
    --out-dir ../../VaneKotlin/library/src/main/java/ \
    --config uniffi.toml \
    --no-format
    # for desktop
    # --library ~/.cargo-target/release/libvane.dylib \
if [ -f ../../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/vane.kt ]; then
    mv ../../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/vane.kt ../../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/Vane.kt
fi
