#!/usr/bin/env python3
"""Patch checked-out source trees temporarily for genuine in-process benchmark."""
import argparse
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("tree")
p.add_argument("--new", action="store_true")
args=p.parse_args()
root=Path(args.tree)
main=root/"main.cpp"
content=main.read_text()
anchor="int main(int argc, char *argv[])"
assert content.count(anchor)==1
injected=("#define NXT_BENCH_NEW 1\n" if args.new else "")+'#include "tests/bench-userlist-driver.h"\n'+anchor
content=content.replace(anchor,injected)
anchor2="thisfile = argv[0];"
assert content.count(anchor2)==1
content=content.replace(anchor2,anchor2+'\n\tif(getenv("NXT_BENCH")) return nxt_userlist_benchmark();')
main.write_text(content)
