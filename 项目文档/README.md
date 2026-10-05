# ObfuscatedStringRecovery

An offline, narrowly scoped stack-string reconstruction lab. It reads a
bounded ELF64 little-endian x86-64 **relocatable object**, walks sized function
symbols, and interprets only a small straight-line instruction subset:
frame-local byte writes, same-slot XOR transformations, and return.
Every recovered ASCII string includes its object-file byte offsets, per-byte
write origins, transformation offsets, and an explicit uncertainty statement.

The scanner never loads or executes inspected object code. Unsupported control
flow, unknown instructions, code relocations, malformed ELF structures, and
unbounded inputs are rejected or recorded as skipped functions. File size,
section count, text size, function count, instructions, writes, findings, and
cooperative elapsed time all have explicit limits. The elapsed-time check is
not an operating-system hard timeout for a blocked filesystem read.

From the repository root, install the build requirements in `Build` and run
`python3 tools/run_validation.py`. Validation compiles only the self-authored
harmless fixtures with Clang; it never runs the resulting ELF objects. The
receipt and all generated files stay under `Build`. The tests compare a
test-only literal-byte baseline, which misses stack-built text, against the
reconstruction of `HELLO` and XOR-decoded `WORLD`. A benign short string
and nonprintable sequence produce no finding, while a conditional function is
explicitly skipped.

The local experiment does not establish reachability in a real program,
complete x86 coverage, a finding in an external sample, an upstream
vulnerability, or CVP eligibility or approval. See [ORIGIN.md](ORIGIN.md) for
the fixed reference and rights boundary.
