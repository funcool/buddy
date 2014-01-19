#!/bin/sh
(cd doc; make)
# lein doc
# lein javadoc
cp -vr doc/index.html /tmp/index.html;
# cp -vr docs/api /tmp/api
git checkout gh-pages;
rm -rf *
mv -fv /tmp/index.html .
# mv -fv /tmp/api .

git add --all index.html
# git add --all api
git commit -a -m "Update doc"
