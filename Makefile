
check:
	cargo c
	cargo fmt -- --check
	cargo clean -p sign-in-with-apple
	cargo clippy
	cargo t

clippy-nightly:
	cargo +nightly clean -p sign-in-with-apple
	cargo +nightly clippy