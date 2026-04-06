#!/usr/bin/env bash
# Fix broken /usr/local/bin/docker symlink (e.g. leftover OrbStack) and point at Docker Desktop.
# Run on your Mac in Terminal:  bash scripts/fix_docker_cli_macos.sh
set -euo pipefail

DOCKER_BIN="/Applications/Docker.app/Contents/Resources/bin/docker"
PLUGIN_DIR="/Applications/Docker.app/Contents/Resources/cli-plugins"

if [[ ! -x "${DOCKER_BIN}" ]]; then
  echo "Docker Desktop CLI not found at: ${DOCKER_BIN}" >&2
  echo "Install or open Docker Desktop from Applications, then run this again." >&2
  exit 1
fi

echo "Using: ${DOCKER_BIN}"
"${DOCKER_BIN}" --version

if [[ -L /usr/local/bin/docker ]] || [[ -f /usr/local/bin/docker ]]; then
  echo "Replacing /usr/local/bin/docker (sudo required)..."
  sudo rm -f /usr/local/bin/docker
fi
sudo ln -sf "${DOCKER_BIN}" /usr/local/bin/docker

echo "Linked /usr/local/bin/docker -> ${DOCKER_BIN}"
/usr/local/bin/docker --version

# Credential helpers (e.g. pulls from Docker Hub) — fixes:
#   error getting credentials - exec: "docker-credential-osxkeychain": executable file not found in $PATH
DD_RESOURCES_BIN="/Applications/Docker.app/Contents/Resources/bin"
if compgen -G "${DD_RESOURCES_BIN}/docker-credential-*" >/dev/null 2>&1; then
  for helper in "${DD_RESOURCES_BIN}"/docker-credential-*; do
    [[ -x "${helper}" ]] || continue
    base="$(basename "${helper}")"
    echo "Linking credential helper: ${base}"
    sudo ln -sf "${helper}" "/usr/local/bin/${base}"
  done
else
  echo "No docker-credential-* binaries under ${DD_RESOURCES_BIN} (skipping)." >&2
fi

if [[ -f "${PLUGIN_DIR}/docker-compose" ]]; then
  mkdir -p "${HOME}/.docker/cli-plugins"
  ln -sf "${PLUGIN_DIR}/docker-compose" "${HOME}/.docker/cli-plugins/docker-compose"
  echo "Linked docker compose plugin to ~/.docker/cli-plugins/"
  /usr/local/bin/docker compose version || true
fi

echo "Done. Open a new terminal and run: docker compose version"
