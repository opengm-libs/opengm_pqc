.PHONY: all build-rust

all: build-rust

build: build-rust

build-rust:
	cargo build --release --target aarch64-apple-darwin
	cp target/aarch64-apple-darwin/release/libopengm_pqc.a libs/libopengm_pqc_aarch64-apple-darwin.a

	cargo build --release --target aarch64-unknown-linux-gnu
	cp target/aarch64-unknown-linux-gnu/release/libopengm_pqc.a libs/libopengm_pqc_aarch64-unknown-linux-gnu.a
	
	cargo build --release --target aarch64-apple-darwin
	cp target/aarch64-apple-darwin/release/libopengm_pqc.a libs/libopengm_pqc_aarch64-apple-darwin.a

	cargo build --release --target x86_64-unknown-linux-gnu
	cp target/x86_64-unknown-linux-gnu/release/libopengm_pqc.a libs/libopengm_pqc_x86_64-unknown-linux-gnu.a

	# this pulls out ELF symbols, 80% size reduction!
	# strip api/libgo_rust_demo.so
