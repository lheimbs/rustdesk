winres 0.1.12 (crates.io, MIT) with one change in `lib.rs`: `write_resource_file` writes the VERSIONINFO fields and
string properties in sorted order instead of `HashMap` iteration order. Upstream's order is random per process, so every
Windows build produced different resource bytes (found by comparing two builds of the installer, plan section 2k).
Wired in with `[patch.crates-io]` in the root `Cargo.toml`.
