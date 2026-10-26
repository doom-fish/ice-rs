//! Build script for `ice-rs`.
//!
//! ICE adds no native dependencies of its own beyond what the sibling
//! `stun-rs` / `turn-rs` / `networkframework` crates already link. The shared
//! UDP socket is built directly on the BSD sockets API from `libc`, which
//! resolves in `libSystem` and needs no extra link flags. The `Security`
//! framework is linked so the transaction-ID RNG (`SecRandomCopyBytes`, reused
//! transitively from `stun-rs`) resolves when `ice-rs` is the top-level crate.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    if std::env::var("DOCS_RS").is_ok() {
        return;
    }

    // SecRandomCopyBytes / kSecRandomDefault (pulled in transitively via stun-rs).
    println!("cargo:rustc-link-lib=framework=Security");
}
