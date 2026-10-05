# Origin and rights

This project is newly written by dhtfish98. Its fixed research reference is
[mandiant/flare-floss at commit 089f3fc7100835459188a61343d8bea3e88b8437](https://github.com/mandiant/flare-floss/commit/089f3fc7100835459188a61343d8bea3e88b8437),
particularly the publicly documented stack-string and decoded-string problem
space. The candidate list identified `floss/stackstrings.py`,
`floss/tightstrings.py`, `floss/string_decoder.py`, and
`floss/decoding_manager.py` as reference paths. No source, test fixture, or
binary from that project is copied, linked, vendored, or redistributed here.

The pinned upstream commit changes string-tag data and tests. It is not
evidence of a defect in upstream string recovery. The upstream work and its
[Apache-2.0 license](https://github.com/mandiant/flare-floss/blob/089f3fc7100835459188a61343d8bea3e88b8437/LICENSE.txt)
remain with their original authors. This project's new code is MIT-licensed
and carries the dhtfish98 copyright notice in `LICENSE`.

At validation time, a separately installed Clang compiles only this project's
harmless C fixtures to ELF relocatable objects. Clang is not bundled. The
scanner itself uses only the Python standard library and never executes the
object under inspection.
