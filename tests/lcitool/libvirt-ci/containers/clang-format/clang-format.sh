#!/bin/sh

git ls-tree --name-only -r HEAD | grep '\.[ch]$' | xargs clang-format -i

git diff > clang-format.patch
if test -s clang-format.patch
then
    echo
    echo "❌ ERROR: some files failed clang-format code style check"
    echo
    git diff --stat
    echo
    echo "See the clang-format patch artifact for full details of mistakes."
    echo
    echo "For guidance on how to configure Emacs or Vim to automatically"
    echo "run clang-format when saving files read"
    echo
    echo "     https://clang.llvm.org/docs/ClangFormat.html"
    echo
    exit 1
fi

echo "✔ OK: all files passed go fmt code style check"
