#!/usr/bin/env bash
# Interactive installation on Ubuntu amd64. No preconfigured .env, Go, Node or registry required.
set +x
set -Eeuo pipefail
umask 077

INSTALL_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
APP_IMAGE=awg-panel:local
RUNTIME_TAG=awg-panel-runtime:local

say() { printf '\n%s\n' "$*"; }
fail() { printf '\nОшибка: %s\n' "$*" >&2; return 1; }
compose() { (cd "$INSTALL_ROOT" && docker compose "$@"); }

usage() {
    cat <<'HELP'
AWG Panel — интерактивная установка

  sudo ./install.sh

Установщик спросит логин, пароль, HTTPS-порт, домен и email для Let's Encrypt.
Домен должен указывать на этот VPS. Откройте TCP 80 и выбранный HTTPS-порт.
Секреты генерируются автоматически; пароль в открытом виде не сохраняется.
Повторный запуск продолжает установку с прежней конфигурацией и секретами.
HELP
}

require_host() {
    [[ $EUID -eq 0 ]] || fail 'Запустите sudo ./install.sh.'
    [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Нужна Ubuntu amd64.'
    # /etc/os-release is OS-owned, never source an application .env file.
    local ID VERSION_ID
    . /etc/os-release
    [[ $ID == ubuntu && ( $VERSION_ID == 22.04 || $VERSION_ID == 24.04 || $VERSION_ID == 26.04 ) ]] || fail 'Поддерживается Ubuntu 22.04, 24.04 или 26.04 amd64.'
    [[ -c /dev/net/tun ]] || fail 'На VPS отсутствует /dev/net/tun. Включите TUN у провайдера.'
    [[ -f "$INSTALL_ROOT/compose.yml" && -f "$INSTALL_ROOT/deploy/compose.installer.yml" ]] || fail 'Запускайте install.sh из полного клона репозитория.'
}

ensure_dependencies() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl iproute2 util-linux
    if ! command -v docker >/dev/null 2>&1; then
        say 'Устанавливаю Docker из официального репозитория Docker.'
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL --retry 3 https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/awg-panel-docker.asc
        chmod 0644 /etc/apt/keyrings/awg-panel-docker.asc
        local VERSION_CODENAME UBUNTU_CODENAME
        . /etc/os-release
        cat > /etc/apt/sources.list.d/awg-panel-docker.sources <<SOURCES
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/awg-panel-docker.asc
SOURCES
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    elif ! docker compose version >/dev/null 2>&1; then
        # Preserve an existing Docker installation and its containers.
        if apt-cache show docker-compose-plugin >/dev/null 2>&1; then
            apt-get install -y docker-compose-plugin
        else
            apt-get install -y docker-compose-v2
        fi
    fi
    systemctl enable --now docker
    docker info >/dev/null
    docker compose version >/dev/null || fail 'Docker Compose v2 недоступен. Установите Compose plugin и повторите запуск.'
}

read_text() {
    local name=$1 label=$2 default=${3:-} value
    if [[ -n $default ]]; then printf '%s [%s]: ' "$label" "$default" >&2; else printf '%s: ' "$label" >&2; fi
    IFS= read -r value || return 1
    printf -v "$name" '%s' "${value:-$default}"
}

prompt_setup() {
    say 'Настройка администратора и HTTPS'
    read_text ADMIN_USERNAME 'Логин администратора' admin
    while :; do
        printf 'Пароль администратора (12–72 байта): ' >&2
        IFS= read -r -s ADMIN_PASSWORD || return 1
        printf '\nПовторите пароль: ' >&2
        local confirmation
        IFS= read -r -s confirmation || return 1
        printf '\n' >&2
        if [[ "$ADMIN_PASSWORD" != "$confirmation" ]]; then say 'Пароли не совпали.'; continue; fi
        local length
        length=$(LC_ALL=C printf '%s' "$ADMIN_PASSWORD" | wc -c)
        if (( length < 12 || length > 72 )); then say 'Пароль должен занимать от 12 до 72 байт.'; continue; fi
        break
    done
    read_text PANEL_PORT 'HTTPS-порт панели' 443
    [[ $PANEL_PORT =~ ^[0-9]{1,5}$ ]] || fail 'Порт должен быть числом.'
    PANEL_PORT=$((10#$PANEL_PORT))
    (( PANEL_PORT >= 1 && PANEL_PORT <= 65535 && PANEL_PORT != 80 )) || fail 'Выберите порт 1–65535, кроме 80.'
    read_text PANEL_DOMAIN 'Домен панели, например panel.example.org'
    PANEL_DOMAIN=$(printf '%s' "$PANEL_DOMAIN" | tr '[:upper:]' '[:lower:]')
    [[ $PANEL_DOMAIN =~ ^[a-z0-9][a-z0-9.-]*\.[a-z][a-z0-9-]*$ ]] || fail 'Укажите домен без https://, пути, порта и wildcard.'
    read_text ACME_EMAIL 'Email для выпуска сертификата'
    say "Сертификат Let's Encrypt будет выпущен для $PANEL_DOMAIN и будет продлеваться автоматически."
    say 'Условия центра сертификации: https://letsencrypt.org/repository/'
    local answer
    read_text answer 'Выпустить и установить сертификат? [д/н]' д
    [[ $answer == д || $answer == Д || $answer == y || $answer == Y || $answer == yes ]] || fail 'Установка отменена.'
}

# Read only nonsecret, validated values. Never execute the contents of .env.
load_existing() {
    grep -qx "INSTALLER_VERSION='1'" "$INSTALL_ROOT/.env" || fail 'Найдена конфигурация, созданная вручную. Она сохранена; автоматическая перезапись секретов запрещена. Используйте отдельный каталог для новой установки.'
    local name value
    while IFS='=' read -r name value; do
        value=${value#\'}; value=${value%\'}
        case "$name" in
            PANEL_DOMAIN) PANEL_DOMAIN=$value ;;
            PANEL_PORT) PANEL_PORT=$value ;;
        esac
    done < "$INSTALL_ROOT/.env"
    [[ ${PANEL_DOMAIN:-} =~ ^[a-z0-9][a-z0-9.-]*\.[a-z][a-z0-9-]*$ && ${PANEL_PORT:-} =~ ^[0-9]{1,5}$ ]] || fail 'Повреждены настройки домена или порта.'
    (( PANEL_PORT >= 1 && PANEL_PORT <= 65535 && PANEL_PORT != 80 )) || fail 'Неверный сохранённый порт.'
    [[ -s "$INSTALL_ROOT/.installer/runtime.tar" ]] || fail 'Отсутствует сохранённый runtime.tar. Восстановите .installer из резервной копии; секреты не изменены.'
    say 'Найдена предыдущая установка. Использую прежние логин, пароль, секреты и runtime.'
}

protect_existing_data() {
    if [[ ! -e "$INSTALL_ROOT/.env" ]]; then
        local containers volumes
        containers=$(docker ps -aq --filter label=com.docker.compose.project=awg-panel)
        volumes=$(docker volume ls -q --filter label=com.docker.compose.project=awg-panel)
        [[ -z $containers && -z $volumes ]] || fail 'Найдены контейнеры или данные AWG Panel без .env в этом каталоге. Используйте исходный каталог или восстановите .env из резервной копии: новые секреты для существующей БД создавать нельзя.'
    fi
}

check_override() {
    local target="$INSTALL_ROOT/compose.override.yml" actual expected
    if [[ -e $target ]] && ! cmp -s "$INSTALL_ROOT/deploy/compose.installer.yml" "$target"; then
        if [[ -f "$INSTALL_ROOT/.installer/compose.sha256" ]]; then
            IFS= read -r expected < "$INSTALL_ROOT/.installer/compose.sha256"
            actual=$(sha256sum "$target"); actual=${actual%% *}
            [[ $actual == "$expected" ]] && return 0
        fi
        fail 'Найден пользовательский compose.override.yml. Он сохранён. Для установки используйте отдельный каталог.'
    fi
}

check_ports() {
    local port own ids id
    own=$(docker ps -q --filter label=com.docker.compose.project=awg-panel --filter label=com.docker.compose.service=caddy)
    for port in 80 "$PANEL_PORT"; do
        ids=$(docker ps -q --filter "publish=$port/tcp")
        for id in $ids; do [[ -n $own && $id == "$own" ]] || fail "TCP-порт $port уже опубликован другим контейнером. Освободите его и повторите установку."; done
        if [[ -n $(ss -H -ltn "sport = :$port") && -z $own ]]; then
            fail "TCP-порт $port занят. Установщик не останавливает чужой Nginx/Apache и другие приложения."
        fi
    done
}

check_dns() {
    getent ahostsv4 "$PANEL_DOMAIN" >/dev/null || fail "Домен $PANEL_DOMAIN пока не разрешается в IPv4. Создайте A-запись на IP этого VPS и повторите запуск."
    say "Проверьте в firewall хостинга доступность TCP 80 и TCP $PANEL_PORT. Запись A домена должна указывать на этот VPS."
}

build_application() {
    say 'Собираю панель. Go и Node на сервер устанавливать не требуется.'
    docker build --platform linux/amd64 -f "$INSTALL_ROOT/deploy/Dockerfile" -t "$APP_IMAGE" "$INSTALL_ROOT"
}

create_configuration() {
    [[ ! -e "$INSTALL_ROOT/.env" ]] || fail 'Конфигурация уже существует; перезапись отменена.'
    say 'Собираю AWG runtime и готовлю архив для доставки по SSH.'
    docker build --platform linux/amd64 -f "$INSTALL_ROOT/deploy/runtime/Dockerfile" -t "$RUNTIME_TAG" "$INSTALL_ROOT/deploy/runtime"
    AWG_RUNTIME_IMAGE=$(docker image inspect --format '{{.Id}}' "$RUNTIME_TAG")
    [[ $AWG_RUNTIME_IMAGE =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'Не удалось получить ID образа AWG.'
    docker image save -o "$INSTALL_ROOT/.installer/runtime.tar.tmp" "$AWG_RUNTIME_IMAGE"
    mv "$INSTALL_ROOT/.installer/runtime.tar.tmp" "$INSTALL_ROOT/.installer/runtime.tar"
    chmod 0600 "$INSTALL_ROOT/.installer/runtime.tar"
    export ADMIN_USERNAME ADMIN_PASSWORD PANEL_DOMAIN PANEL_PORT ACME_EMAIL AWG_RUNTIME_IMAGE
    # Password is passed by inherited environment, never as a command argument or persisted plaintext.
    docker run --rm --entrypoint check \
        -e ADMIN_USERNAME -e ADMIN_PASSWORD -e PANEL_DOMAIN -e PANEL_PORT -e ACME_EMAIL -e AWG_RUNTIME_IMAGE \
        "$APP_IMAGE" install > "$INSTALL_ROOT/.installer/config.tmp"
    unset ADMIN_PASSWORD
    chmod 0600 "$INSTALL_ROOT/.installer/config.tmp"
    # Link is atomic and refuses to replace an existing configuration, even after an interrupted run.
    ln "$INSTALL_ROOT/.installer/config.tmp" "$INSTALL_ROOT/.env"
    rm "$INSTALL_ROOT/.installer/config.tmp"
}

prepare_stack() {
    check_override
    cp "$INSTALL_ROOT/deploy/compose.installer.yml" "$INSTALL_ROOT/.installer/compose.override.tmp"
    mv "$INSTALL_ROOT/.installer/compose.override.tmp" "$INSTALL_ROOT/compose.override.yml"
    local checksum
    checksum=$(sha256sum "$INSTALL_ROOT/compose.override.yml"); printf '%s\n' "${checksum%% *}" > "$INSTALL_ROOT/.installer/compose.sha256"
    compose config --quiet
    compose run --rm --no-deps --entrypoint caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
    compose up -d db api worker caddy
}

wait_https() {
    local url="https://$PANEL_DOMAIN" deadline=$((SECONDS + 300))
    if [[ $PANEL_PORT != 443 ]]; then url+=":$PANEL_PORT"; fi
    say "Ожидаю действительный сертификат и готовность $url (до 5 минут)."
    while (( SECONDS < deadline )); do
        if curl --fail --silent --show-error --noproxy '*' \
            --connect-timeout 3 --max-time 10 \
            --resolve "$PANEL_DOMAIN:$PANEL_PORT:127.0.0.1" "$url/healthz" >/dev/null 2>&1; then
            say "Панель установлена: $url"
            say 'Войдите с указанными логином и паролем. Caddy автоматически продлевает сертификат; TCP 80 оставьте открытым.'
            say "Сохраните резервную копию $INSTALL_ROOT/.env и volume с БД."
            return 0
        fi
        sleep 3
    done
    fail 'HTTPS не подтвердился. Проверьте A/AAAA-записи, firewall и docker compose logs caddy. Настройки и ключи сохранены; после исправления повторите sudo ./install.sh.'
}

main() {
    case ${1:-} in --help|-h) usage; return ;; '') ;; *) usage; return 1 ;; esac
    cd "$INSTALL_ROOT"
    require_host
    install -d -m 0700 "$INSTALL_ROOT/.installer"
    exec 9>"$INSTALL_ROOT/.installer/install.lock"
    flock -n 9 || fail 'Другой установщик уже работает.'
    trap 'unset ADMIN_PASSWORD; printf "\nУстановка остановлена. Конфигурация и Docker volumes не удалены.\n" >&2' ERR
    unset ADMIN_PASSWORD
    ensure_dependencies
    protect_existing_data
    check_override
    if [[ -e "$INSTALL_ROOT/.env" ]]; then load_existing; else prompt_setup; fi
    check_ports
    check_dns
    build_application
    if [[ ! -e "$INSTALL_ROOT/.env" ]]; then create_configuration; fi
    prepare_stack
    wait_https
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
