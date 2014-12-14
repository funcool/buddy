#!/bin/sh
VERSION="0.2.x"

lein doc
(cd doc; make)

rm -rf /tmp/index.html /tmp/api

mv doc/index.html /tmp/index.html;
mv doc/api /tmp/api

git checkout gh-pages;

rm -rf ./$VERSION
mkdir -p ./$VERSION/
mv -fv /tmp/index.html ./$VERSION/
mv -fv /tmp/api ./$VERSION/
git add --all ./$VERSION/index.html
git add --all ./$VERSION/api
git commit -a -m "Update ${VERSION} doc"
