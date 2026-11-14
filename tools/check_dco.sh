#!/usr/bin/env bash
# Check the Developer Certificate of Origin sign-off (CONTRIBUTING.md) on
# every commit in BASE..HEAD: each one needs a `Signed-off-by:` line with its
# author's email. Merge commits are skipped; the commits they bring in are
# checked on their own.
#
#   tools/check_dco.sh origin/main HEAD
#
# CI runs it on each pull request (.github/workflows/dco.yml). A commit
# without one is fixed with `git commit --amend -s` for the last commit, or
# `git rebase --signoff BASE` for all of them, and a force-push.
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 BASE HEAD" >&2
    exit 2
fi

base=$1
head=$2
failed=0
checked=0

for commit in $(git rev-list --no-merges --reverse "$base..$head"); do
    checked=$((checked + 1))
    short=$(git log -1 --format=%h "$commit")
    email=$(git log -1 --format=%ae "$commit")
    signoffs=$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$commit")
    if [ -n "$email" ] && grep -qiF -- "<$email>" <<<"$signoffs"; then
        echo "ok      $short  signed off by <$email>"
    else
        # The ::error:: prefix makes GitHub show the line on the pull request.
        echo "::error::Commit $short has no Signed-off-by: line with its author's email <$email>. Sign it off with git commit --amend -s (last commit) or git rebase --signoff $base (all), then force-push."
        failed=$((failed + 1))
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "$failed of $checked commit(s) are not signed off. See CONTRIBUTING.md."
    exit 1
fi
echo "All $checked commit(s) are signed off."
