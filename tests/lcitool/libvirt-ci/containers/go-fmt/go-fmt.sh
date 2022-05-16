#!/bin/sh

GOFMT=$(go env GOROOT)/bin/gofmt

find -name '*.go' | xargs $GOFMT -d -e > go-fmt.patch

if test -s go-fmt.patch
then
    echo
    echo "❌ ERROR: some files failed go fmt code style check"
    echo
    diffstat go-fmt.patch
    echo
    echo "See the go-fmt patch artifact for full details of mistakes."
    echo
    echo "For guidance on how to configure Emacs or Vim to automatically"
    echo "run go fmt when saving files read"
    echo
    echo "     https://blog.golang.org/gofmt"
    echo
    exit 1
fi

echo "✔ OK: all files passed go fmt code style check"
