# Golden path: one command, the whole canonical loop.
demo:
	./golden/demo.sh

# Regression + verification + golden path + deterministic fuzz harness.
test:
	cargo test

# Regression suite only (invariant bank).
regression:
	cargo test --test regression --test golden_path

# Verification suite: re-derive the checked-in evidence tree with the tool's
# own pure functions. Fails if any generated artifact was hand-edited.
verify:
	cargo test --test verify_tree

# OpenReceipt conformance suite: the protocol corpus (valid/invalid/canonical/hashes)
conformance:
	cargo test --test conformance

# Independent verifier: the Python SECOND implementation proves the protocol
# separation — same corpus, same bundle, no frf binary (needs python3 + PyYAML).
independent:
	cargo test --test independent
	python3 verifier/frf_verify.py corpus conformance
	python3 verifier/frf_verify.py bundle golden/work/portable.frf

# Deterministic in-repo fuzz harness (no nightly needed); scale with
# FRF_FUZZ_ITERS, e.g. make fuzz-iters FRF_FUZZ_ITERS=200000
fuzz-iters:
	FRF_FUZZ_ITERS=$${FRF_FUZZ_ITERS:-100000} cargo test --test fuzz

# libFuzzer targets (needs nightly + clang + cargo-fuzz): cargo +nightly fuzz run <target>
fuzz:
	@echo "targets: yaml_types cli_args store_ids"
	@echo "run e.g.:  cargo +nightly fuzz run yaml_types"

build:
	cargo build --release

install:
	cargo install --path .
