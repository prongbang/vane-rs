# `--library` was dropped in uniffi 0.31: a `.dylib`/`.so`/`.a` argument is
# detected as a library automatically. Stay on the flat `--config uniffi.toml`
# form — uniffi 0.32 ignores it silently, which would drop `package_name` and
# regenerate Kotlin into the wrong package.
cargo run \
    --bin uniffi-bindgen generate ~/.cargo-target/release/libvane.dylib \
    --language kotlin \
    --out-dir ../../VaneKotlin/library/src/main/java/ \
    --config uniffi.toml \
    --no-format
if [ -f ../../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/vane.kt ]; then
    mv ../../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/vane.kt ../../VaneKotlin/library/src/main/java/com/inteniquetic/vanekotlin/Vane.kt
fi
