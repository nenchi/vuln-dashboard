#!/bin/sh
# Runs after a Renovate merge to main (docker-publish.yml, release job). If the Dockerfile base image changed:
# bump the patch version (app/app.py VERSION + README examples), commit, tag, write release-notes.md and
# version=X.Y.Z to $GITHUB_OUTPUT. Pushing and the GitHub Release are done by the workflow. Otherwise: nothing.
set -eu

old_from=$(git show HEAD~1:Dockerfile | sed -n 's/^FROM //p')
new_from=$(sed -n 's/^FROM //p' Dockerfile)
if [ "$old_from" = "$new_from" ]; then
  echo "Base image unchanged ($new_from): no release"
  exit 0
fi

old=$(sed -n 's/^VERSION = "\(.*\)".*/\1/p' app/app.py)
new=$(echo "$old" | awk -F. '{ print $1 "." $2 "." $3 + 1 }')
old_re=$(echo "$old" | sed 's/\./\\./g')
sed -i "s/^VERSION = \"$old_re\"/VERSION = \"$new\"/" app/app.py
sed -i "s/vuln-dashboard:$old_re\b/vuln-dashboard:$new/g; s|/v$old_re/|/v$new/|g" README.md
grep -q "^VERSION = \"$new\"" app/app.py || { echo "could not bump VERSION in app/app.py"; exit 1; }

# python:3.13.8-alpine -> "Python 3.13.8"; any other base image is shown as is
name() { case "$1" in python:*) v=${1#python:}; echo "Python ${v%%-*}" ;; *) echo "$1" ;; esac; }
change="Bump $(name "$old_from") → $(name "$new_from") (base image \`$old_from\` → \`$new_from\`)"

git add app/app.py README.md
git commit -q -m "Release v$new: $(name "$old_from") → $(name "$new_from")"
git tag -a "v$new" -m "v$new"
cat > release-notes.md <<NOTES
Automatic release after a Renovate update. Unit tests and the container end-to-end test passed before the merge.

## Changed
- $change
- From: $(git log -1 --format=%s HEAD~1)

Image: \`ghcr.io/${GITHUB_REPOSITORY:-nenchi/vuln-dashboard}:$new\`
NOTES
echo "version=$new" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "Released v$new: $change"
