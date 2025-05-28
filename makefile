.PHONY: all build-rust

all: release

release_targets := aarch64-apple-darwin \
aarch64-unknown-linux-gnu \
x86_64-apple-darwin \
x86_64-unknown-linux-gnu \
x86_64-pc-windows-gnu \
loongarch64-unknown-linux-gnu

dev_target := aarch64-apple-darwin

release:
	@for a in $(release_targets);do\
		cargo build --release --features build-lib --target $$a;\
		cp target/$$a/release/libopengm_pqc.a goapi/libs/libopengm_pqc_$$a.a;\
	done

dev:
	@for a in $(dev_target);do\
		cargo build --release --features build-lib --target $$a;\
		cp target/$$a/release/libopengm_pqc.a goapi/libs/libopengm_pqc_$$a.a;\
	done



