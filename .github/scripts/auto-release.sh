#!/bin/sh
# Runs after a Renovate merge to main (docker-publish.yml, release job). If the Dockerfile base image or a cdnjs
# library pinned in site/index.html (Chart.js) changed: bump the patch version (app/app.py VERSION + README examples), commit, tag, write release-notes.md and
# version=X.Y.Z to $GITHUB_OUTPUT. Pushing and the GitHub Release are done by the workflow. Otherwise: nothing.
set -eu

old_from=$(git show HEAD~1:Dockerfile | sed -n 's/^FROM //p')
new_from=$(sed -n 's/^FROM //p' Dockerfile)
# cdnjs libraries as "Chart.js/4.6.1", one per line
libs() { grep -o 'cdnjs\.cloudflare\.com/ajax/libs/[^/]*/[^/]*' | sed 's#.*/libs/##' | sort -u; }
old_libs=$(git show HEAD~1:site/index.html | libs)
new_libs=$(libs < site/index.html)
if [ "$old_from" = "$new_from" ] && [ "$old_libs" = "$new_libs" ]; then
  echo "Base image and cdnjs libraries unchanged ($new_from, $(echo $new_libs)): no release"
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
changes="" title=""
add() { changes="$changes
- $1"; title="${title:+$title, }$2"; }
if [ "$old_from" != "$new_from" ]; then
  if [ "${old_from%@*}" = "${new_from%@*}" ]; then  # digest update: same tag, rebuilt upstream with Alpine fixes
    add "Rebuilt base image \`${new_from%@*}\` (new digest \`${new_from#*@}\`, Alpine package fixes)" "rebuilt $(name "$new_from") base image"
  else
    add "Bump $(name "$old_from") → $(name "$new_from") (base image \`$old_from\` → \`$new_from\`)" "$(name "$old_from") → $(name "$new_from")"
  fi
fi
if [ "$old_libs" != "$new_libs" ]; then  # "Chart.js/4.5.1" -> "Chart.js 4.5.1"
  o=$(echo $old_libs | tr / ' ') n=$(echo $new_libs | tr / ' ')
  add "Bump $o → $n (dashboard page, loaded from cdnjs)" "$n"
fi

git add app/app.py README.md
git commit -q -m "Release v$new: $title"
git tag -a "v$new" -m "v$new"
# a PR merged by hand is a merge commit: show the PR title, not "Merge pull request #N from ..."
from=$(git log -1 --format=%s HEAD~1)
case "$from" in "Merge pull request #"*) n=${from#Merge pull request #}; from="$(git log -1 --format=%b HEAD~1 | head -1) (#${n%% *})" ;; esac
cat > release-notes.md <<NOTES
Automatic release after a Renovate update. Unit tests and the container end-to-end test passed before the merge.

## Changed$changes
- From: $from

Image: \`ghcr.io/${GITHUB_REPOSITORY:-nenchi/vuln-dashboard}:$new\`
NOTES
echo "version=$new" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "Released v$new: $title"
