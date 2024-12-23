.PHONY: all build-rust

all: build-rust

build: build-rust

targets := aarch64-apple-darwin x86_64-apple-darwin \
aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu \
x86_64-pc-windows-gnu\
loongarch64-unknown-linux-gnu

build-rust:
	@for a in $(targets);do\
		cargo build --release --features build-lib --target $$a;\
		cp target/$$a/release/libopengm_pqc.a libs/libopengm_pqc_$$a.a;\
	done


