#!/bin/sh
# Publish the reviewed source and submit its Omarchy marketplace listing.
set -eu
cd "$(dirname "$0")"

repository=sjmaquina/ssh-desk
marketplace=omacom/omarchy-plugin-marketplace

command -v gh >/dev/null 2>&1 || {
    echo 'Install GitHub CLI (gh), then run gh auth login and retry.' >&2
    exit 1
}
gh auth status
account=$(gh api user --jq .login)
[ "$account" = sjmaquina ] || {
    echo 'Authenticate as sjmaquina with gh auth login before publishing.' >&2
    exit 1
}
[ -z "$(git status --porcelain)" ] || {
    echo 'The checkout has uncommitted files. Review and commit them before publishing.' >&2
    exit 1
}
omarchy plugin validate .

if privacy=$(gh repo view "$repository" --json isPrivate --jq .isPrivate 2>/dev/null); then
    [ "$privacy" = false ] || {
        echo 'The existing repository is private. Choose a public repository before submitting.' >&2
        exit 1
    }
    if remote_url=$(git remote get-url origin 2>/dev/null); then
        case "$remote_url" in
            https://github.com/sjmaquina/ssh-desk|https://github.com/sjmaquina/ssh-desk.git|git@github.com:sjmaquina/ssh-desk.git) ;;
            *) echo 'origin points to a different repository; review it before publishing.' >&2; exit 1 ;;
        esac
    else
        git remote add origin https://github.com/sjmaquina/ssh-desk.git
    fi
    git push -u origin main
else
    gh repo create "$repository" --public --source=. --remote=origin --push \
        --description 'Retro SSH connection manager with encrypted profiles and an Omarchy bar launcher'
fi

existing=$(gh issue list --repo "$marketplace" --state all \
    --search 'in:body "https://github.com/sjmaquina/ssh-desk"' \
    --json url --jq '.[0].url // empty')
if [ -n "$existing" ]; then
    echo "A marketplace submission already exists: $existing"
    exit 0
fi

submission=$(mktemp)
trap 'rm -f "$submission"' EXIT HUP INT TERM
sed 's/^- \[ \] The repository is public/- [x] The repository is public/' \
    MARKETPLACE_SUBMISSION.md > "$submission"
gh issue create --repo "$marketplace" --title '[Plugin]: SSH Desk' \
    --label submission --body-file "$submission"
