#!/bin/bash
# 生成并推送订阅（供 launchd 每小时调用）
cd "$(dirname "$0")" || exit 1
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"
export TZ=Asia/Shanghai
export GIT_SSH_COMMAND="ssh -i $PWD/../.keys/id_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=20"
PYTHONPATH="$PWD/vendor" /usr/bin/python3 sub_build.py >> run.log 2>&1
git add -A sub/ >> run.log 2>&1
if ! git diff --cached --quiet; then
  git -c user.name="ioshkj" -c user.email="ioshkj@users.noreply.github.com" commit -q -m "update"
  for i in 1 2 3; do git push -q origin main && break; sleep 10; done
fi
