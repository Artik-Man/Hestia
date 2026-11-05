#!/bin/sh
# Publish committed work to the same branch on origin with one patch bump per batch.
set -eu
branch=$(git symbolic-ref --short HEAD)
if [ -n "$(git status --porcelain)" ]; then
    echo "Сначала закоммитьте изменения: для make push нужно чистое рабочее дерево." >&2
    exit 1
fi
ref="refs/heads/$branch"
remote_refs=$(git ls-remote --refs origin "$ref")
remote_head=$(printf '%s' "$remote_refs" | cut -f1)
if [ "$remote_head" = "$(git rev-parse HEAD)" ]; then
    echo "Все коммиты уже отправлены."
    exit 0
fi
if [ -n "$remote_head" ] && ! git merge-base --is-ancestor "$remote_head" HEAD; then
    echo "Сначала синхронизируйте локальную ветку с origin." >&2
    exit 1
fi
version=$(cd frontend && node -p 'require("./package.json").version')
if [ "$(git log -1 --format=%s)" != "Версия Гестии $version" ]; then
    (cd frontend && npm version patch --no-git-tag-version --ignore-scripts)
    version=$(cd frontend && node -p 'require("./package.json").version')
    git commit -m "Версия Гестии $version" -- frontend/package.json frontend/package-lock.json
fi
git push origin "HEAD:$ref"
