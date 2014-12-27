#!/bin/sh
VERSION="devel"

(cd doc; make)

rm -rf /tmp/buddy-doc/
mkdir -p /tmp/buddy-doc/
mv doc/*.html /tmp/buddy-doc/

git checkout gh-pages;

rm -rf ./$VERSION
mv /tmp/buddy-doc/ ./$VERSION

git add --all ./$VERSION
git commit -a -m "Update ${VERSION} doc"
