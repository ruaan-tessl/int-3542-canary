#!/usr/bin/env bash
# Probe 11 (INT-1459): which processes expose each sandbox credential, what the
# artifact STS session can reach, and whether user code can read another
# process's memory. Prints names, pids, comms, uids and HTTP status codes only.
# It never prints a credential value.
set -u

names="TESSL_ARTIFACT_AWS_ACCESS_KEY_ID TESSL_ARTIFACT_AWS_SECRET_ACCESS_KEY TESSL_ARTIFACT_AWS_SESSION_TOKEN RECIPE_RUN_ENCRYPTED_ENV_PRIVATE_KEY TESSL_GITHUB_APP_PRIVATE_KEY CURSOR_API_KEY KIMI_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY AWS_SECRET_ACCESS_KEY TESSL_TOKEN"

echo "whoami=$(id -un) uid=$(id -u) self_pid=$$"
echo "ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo absent)"
echo "artifact_file=$([ -e /tmp/artifact-credentials.json ] && echo present || echo absent)"
echo "env_key_file=$([ -e /tmp/encrypted-env.key ] && echo present || echo absent)"

# 1. Inventory: own env, then every readable /proc/<pid>/environ.
for n in $names; do
  own=$(env | grep -c "^${n}=")
  hits=""
  for d in /proc/[0-9]*; do
    if tr '\0' '\n' <"$d/environ" 2>/dev/null | grep -q "^${n}="; then
      hits="$hits ${d#/proc/}:$(cat "$d/comm" 2>/dev/null):$(awk '/^Uid:/{print $2}' "$d/status" 2>/dev/null)"
    fi
  done
  count=$(echo "$hits" | wc -w | tr -d ' ')
  echo "inventory name=$n own_env=$own procs=$count${hits:+ [$hits ]}"
done

# 2. STS reach, using the session found in another process's environ.
src=""
for d in /proc/[0-9]*; do
  if tr '\0' '\n' <"$d/environ" 2>/dev/null | grep -q '^TESSL_ARTIFACT_AWS_SESSION_TOKEN='; then
    src=$d
    break
  fi
done
getv() { tr '\0' '\n' <"$src/environ" 2>/dev/null | sed -n "s/^$1=//p" | head -1; }

if [ -z "$src" ]; then
  echo "sts_source=none"
  echo "VERDICT_STS=NOT_IN_ANY_ENVIRON"
else
  AK=$(getv TESSL_ARTIFACT_AWS_ACCESS_KEY_ID)
  SK=$(getv TESSL_ARTIFACT_AWS_SECRET_ACCESS_KEY)
  ST=$(getv TESSL_ARTIFACT_AWS_SESSION_TOKEN)
  BUCKET=$(getv TESSL_ARTIFACT_S3_BUCKET)
  PREFIX=$(getv TESSL_ARTIFACT_S3_KEY_PREFIX)
  REGION=$(getv TESSL_ARTIFACT_S3_REGION)
  REGION=${REGION:-us-east-1}
  echo "sts_source=pid${src#/proc/} comm=$(cat "$src/comm" 2>/dev/null) bucket_set=$([ -n "$BUCKET" ] && echo yes || echo no) prefix_set=$([ -n "$PREFIX" ] && echo yes || echo no) prefix_ends_slash=$(case "$PREFIX" in */) echo yes ;; *) echo no ;; esac) region=$REGION"
  host="https://${BUCKET}.s3.${REGION}.amazonaws.com"
  enc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
  # Credentials go to curl on stdin, never on argv.
  s3() {
    printf 'user = "%s:%s"\nheader = "x-amz-security-token: %s"\n' "$AK" "$SK" "$ST" |
      curl -s -o /dev/null -w '%{http_code}' -K - --aws-sigv4 "aws:amz:${REGION}:s3" "$@"
  }
  case "$PREFIX" in */) own="$PREFIX" ;; *) own="$PREFIX/" ;; esac
  echo "s3 list_own_prefix=$(s3 "${host}/?list-type=2&max-keys=1&prefix=$(enc "$own")") (expect 200)"
  echo "s3 list_bucket_root=$(s3 "${host}/?list-type=2&max-keys=1") (expect 403)"
  echo "s3 list_sibling_prefix=$(s3 "${host}/?list-type=2&max-keys=1&prefix=$(enc "int1459-sibling-probe/")") (expect 403)"
  key="${own}int1459-probe/$(date -u +%Y%m%dT%H%M%SZ).txt"
  echo "s3 put_new_object_own_prefix=$(s3 -X PUT --data-binary 'int1459 probe marker' "${host}/${key}") (200 = user code can write anywhere under the run prefix, including sys-log.jsonl)"
  echo "s3 put_outside_prefix=$(s3 -X PUT --data-binary 'int1459 probe marker' "${host}/int1459-sibling-probe/marker.txt") (expect 403)"
  unset AK SK ST
  echo "VERDICT_STS=IN_ENVIRON (see s3 lines for reach)"
fi

# 3. Memory read: try to read 16 bytes from the first readable mapping of every
# other process. Expected under ptrace_scope=1: denied for all non-descendants.
python3 - "$$" <<'PY'
import os, sys
self_pid = int(sys.argv[1])
ok = denied = 0
for name in sorted(os.listdir('/proc'), key=lambda s: (len(s), s)):
    if not name.isdigit():
        continue
    pid = int(name)
    if pid in (self_pid, os.getpid(), os.getppid()):
        continue
    try:
        comm = open(f'/proc/{pid}/comm').read().strip()
        maps = open(f'/proc/{pid}/maps').read().splitlines()
    except OSError as e:
        print(f"mem pid={pid} maps=unreadable:{e.errno}")
        continue
    addr = next((int(l.split()[0].split('-')[0], 16) for l in maps if l.split()[1].startswith('r') and not l.rstrip().endswith(('[vvar]', '[vsyscall]', '[vvar_vclock]'))), None)
    if addr is None:
        continue
    try:
        with open(f'/proc/{pid}/mem', 'rb') as f:
            f.seek(addr)
            f.read(16)
        ok += 1
        print(f"mem pid={pid} comm={comm} read=OK")
    except OSError as e:
        denied += 1
        print(f"mem pid={pid} comm={comm} read=denied:errno{e.errno}")
print(f"mem_summary readable={ok} denied={denied}")
print("VERDICT_MEM=" + ("READABLE" if ok else "PROTECTED"))
PY
echo DONE
