#!/usr/bin/env bash
# INT-1459 rollout check: for each variable name, count the processes whose
# environment lists it. Prints names and counts only.
set -u
echo "artifact_file=$([ -e /tmp/artifact-credentials.json ] && echo present || echo absent)"
echo "env_key_file=$([ -e /tmp/encrypted-env.key ] && echo present || echo absent)"
for n in TESSL_ARTIFACT_AWS_SESSION_TOKEN TESSL_ARTIFACT_S3_BUCKET RECIPE_RUN_ENCRYPTED_ENV_PRIVATE_KEY TESSL_GITHUB_APP_PRIVATE_KEY CURSOR_API_KEY; do
  c=0
  for d in /proc/[0-9]*; do
    tr '\0' '\n' <"$d/environ" 2>/dev/null | grep -q "^${n}=" && c=$((c + 1))
  done
  echo "name=$n processes=$c pid1=$(tr '\0' '\n' </proc/1/environ 2>/dev/null | grep -c "^${n}=")"
done
