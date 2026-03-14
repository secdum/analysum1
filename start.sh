#!/bin/bash
set -e

cd /home/runner/actions-runner

if [ -z "$REPO_URL" ]; then
  echo "REPO_URL não definida"
  exit 1
fi

if [ -z "$RUNNER_TOKEN" ]; then
  echo "RUNNER_TOKEN não definida"
  exit 1
fi

if [ -z "$RUNNER_NAME" ]; then
  RUNNER_NAME="docker-self-hosted-runner"
fi

if [ -z "$RUNNER_LABELS" ]; then
  RUNNER_LABELS="self-hosted,linux,x64,docker-runner"
fi

cleanup() {
  echo "A remover runner..."
  if [ -n "$RUNNER_REMOVE_TOKEN" ]; then
    ./config.sh remove --unattended --token "$RUNNER_REMOVE_TOKEN" || true
  fi
}

trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

./config.sh --unattended \
  --url "$REPO_URL" \
  --token "$RUNNER_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "$RUNNER_LABELS" \
  --work "_work" \
  --replace

exec ./run.sh