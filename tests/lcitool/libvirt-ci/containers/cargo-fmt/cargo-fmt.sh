#!/bin/sh

cargo fmt -- --check > cargo-fmt.txt

if test -s cargo-fmt.txt
then
    echo
    echo "❌ ERROR: some files failed cargo fmt code style check"
    echo
    echo "See the cargo-fmt.txt artifact for full details of mistakes."
    echo
    echo "For guidance on how to configure Emacs or Vim to automatically"
    echo "run cargo fmt when saving files read"
    echo
    echo "     https://github.com/rust-lang/rustfmt"
    echo
    exit 1
fi

echo "✔ OK: all files passed cargo fmt code style check"
