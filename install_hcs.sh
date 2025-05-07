#!/usr/bin/env bash
# install_hcs.sh – bootstrap Hostile-Command-Suite on Arch Linux
# run:  bash install_hcs.sh   (as a user with sudo)

set -euo pipefail
IFS=$'\n\t'

# -------------------------------------------------------------------
# settings – tweak if you like
# -------------------------------------------------------------------
AUR_PKGS=(
  spiderfoot
  recon-ng
  phoneinfoga-bin
  #theharvester-git
  mosint
  holehe
  sherlock-git
  #twint
)
PY_PKGS=(
  fastmcp
  psycopg2-binary
  rich
  duckduckgo-search
  h8mail
  instaloader
  social-analyzer
)
DB_USER=osint_user
DB_PASS=changeme
DB_NAME=osint_db
VENV_DIR=".venv"
GHUNT_DIR="$HOME/GHunt"

# -------------------------------------------------------------------
log() { printf '\e[1;35m==>\e[0m %s\n' "$*"; }

need_cmd() { command -v "$1" &>/dev/null; }

install_base() {
  log "Updating system and installing base packages"
  sudo pacman -Sy --noconfirm --needed base-devel git python python-pip python-virtualenv postgresql
}

install_yay() {
  if ! need_cmd yay; then
    log "Installing yay (AUR helper)"
    git clone https://aur.archlinux.org/yay.git /tmp/yay
    pushd /tmp/yay >/dev/null
    makepkg -si --noconfirm
    popd >/dev/null
  else
    log "yay already present"
  fi
}

install_aur_pkgs() {
  log "Installing AUR + repo packages"
  yay -S --needed --noconfirm "${AUR_PKGS[@]}"
}

setup_postgres() {
  local PGDATA=/var/lib/postgres/data
  local SVC=postgresql

  # 1. initialise only once
  if [ ! -f "${PGDATA}/PG_VERSION" ]; then
    log "Initialising PostgreSQL cluster"
    sudo -iu postgres initdb -D "${PGDATA}"
  else
    log "PostgreSQL cluster already initialised – skipping initdb"
  fi

  # 2. ensure service is running
  sudo systemctl enable --now "${SVC}"

  # 3. wait until the socket responds
  log "Waiting for Postgres to accept connections..."
  until sudo -iu postgres pg_isready -q; do sleep 0.5; done

  # 4. idempotent role & db creation
  if ! sudo -iu postgres psql -tAc \
        "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}';" | grep -q 1; then
    log "Creating role ${DB_USER}"
    sudo -iu postgres psql -c \
      "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';"
  fi

  if ! sudo -iu postgres psql -lqt | cut -d\| -f1 | grep -qw "${DB_NAME}"; then
    log "Creating database ${DB_NAME}"
    sudo -iu postgres createdb -O "${DB_USER}" "${DB_NAME}"
  fi
}



create_venv() {
  log "Creating Python virtualenv in ${VENV_DIR}"
  python -m venv "${VENV_DIR}"
  # shellcheck source=/dev/null
  source "${VENV_DIR}/bin/activate"
  pip install --upgrade pip
  pip install "${PY_PKGS[@]}"
}

install_ghunt() {
  if [ ! -d "${GHUNT_DIR}" ]; then
    log "Cloning GHunt"
    git clone https://github.com/mxrch/GHunt "${GHUNT_DIR}"
    pushd "${GHUNT_DIR}" >/dev/null
    # reuse venv
    # pip install -r requirements.txt
    popd >/dev/null
  else
    log "GHunt already cloned"
  fi
}

main() {
  install_base
  install_yay
  install_aur_pkgs
  setup_postgres
  create_venv
  install_ghunt

  cat <<EOF

🎉  All done.

Next steps:
1. Add the following to your shell or systemd unit:
   export OSINT_PG_DSN="dbname=${DB_NAME} user=${DB_USER} password=${DB_PASS} host=/var/run/postgresql"
2. Activate the venv when working in the repo:
   source ${VENV_DIR}/bin/activate
3. Optionally run OSINT/db_schema.sql against ${DB_NAME} if you haven't.

Happy hunting! 🦇
EOF
}

main "$@"
