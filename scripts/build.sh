#!/bin/bash

# @brief Полная установка и запуск quic-proxy с проверкой SSL-ключей и управлением systemd
# @warning Требует прав root. Не запускать от обычного пользователя.
# @warning Требует установленных: cmake, make, g++-12, systemctl, acme.sh (для SSL)
# @throws Exit 1 при отсутствии прав root, ошибке компиляции, отсутствии скрипта check_ssl.sh
# @throws Exit 1 при сбое в работе systemd или отсутствии сервиса quic-proxy.service

# Включаем строгий режим
set -e -u -o pipefail

# Цвета для вывода
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
NC='\e[0m' # No Color

# Глобальные переменные
NAME="erosj"
DOMAIN="${NAME}.com"
PROJECT_DIR="/var/www/${NAME}"
QUIC_PROXY_DIR="/opt/quic-proxy"

# @brief Проверяет, запущен ли скрипт от root
# @throws Exit 1 если EUID != 0
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        printf "${RED}❌ 💀 Пожалуйста, запустите этот скрипт с правами root (sudo). 💀${NC}\n" >&2
        exit 1
    fi
}

# @brief Переходит в указанную директорию и выходит с ошибкой при неудаче
# @param dir Путь к директории
# @throws Exit 1 если директория не существует или недоступна
cd_or_exit() {
    local dir="$1"
    cd "$dir" || { printf "${RED}❌ Не удалось перейти в каталог $dir${NC}\n" >&2; exit 1; }
}

# @brief Проверяет наличие файла и делает его исполняемым
# @param script_path Путь к скрипту
# @throws Exit 1 если файл не существует
ensure_script_executable() {
    local script_path="$1"
    if [[ ! -f "$script_path" ]]; then
        printf "${RED}❌ Скрипт $script_path не найден. Не удалось проверить SSL-ключи.${NC}\n" >&2
        exit 1
    fi
    chmod +x "$script_path"
}

# @brief Выполняет команду и проверяет её успешность
# @param cmd Команда для выполнения
# @throws Exit 1 если команда завершилась с ненулевым кодом
run_and_check() {
    local cmd="$1"
    printf "${BLUE}▶️ Выполняю: $cmd${NC}\n" >&2
    eval "$cmd" || { printf "${RED}❌ Ошибка при выполнении: $cmd${NC}\n" >&2; exit 1; }
}

# @brief Перезапускает службу systemd и проверяет статус
# @param service_name Имя службы
# @throws Exit 1 если служба не запустилась
restart_service() {
    local service_name="$1"
    printf "${GREEN}✅ Перезапускаем службу $service_name...${NC}\n" >&2
    systemctl restart "$service_name" || { printf "${RED}❌ Не удалось перезапустить службу $service_name${NC}\n" >&2; exit 1; }

    printf "${GREEN}✅ Проверяем статус службы $service_name...${NC}\n" >&2
    systemctl is-active --quiet "$service_name" || { printf "${RED}❌ Служба $service_name не активна после перезапуска${NC}\n" >&2; exit 1; }
}

# ==== НАЧАЛО СКРИПТА ====

printf "${CYAN}✅ 🇷🇺 ⚠️ 💀 Запуск файла scripts/build.sh 💀 ⚠️ 🇷🇺 ✅ ${NC}\n" >&2

# Проверка прав root
check_root

printf "${GREEN}✅ Начинаем установку и запуск quic-proxy...${NC}\n" >&2

# Переходим в каталог проекта
cd_or_exit "$QUIC_PROXY_DIR"

# Удаляем старую директорию сборки
printf "${BLUE}▶️ Удаляем старую директорию build...${NC}\n" >&2
rm -rf build

# Создаём и переходим в директорию сборки
printf "${GREEN}✅ Создаём директорию сборки и собираем проект...${NC}\n" >&2
mkdir -p build
cd_or_exit build

# Конфигурируем проект через CMake
run_and_check "cmake .. -DCMAKE_CXX_COMPILER=g++-12 -DCMAKE_CXX_STANDARD=23"

# Собираем проект
run_and_check "make -j\$(nproc)"

# Устанавливаем бинарник и сервис
printf "${GREEN}✅ Устанавливаем бинарник и сервис...${NC}\n" >&2
run_and_check "sudo make install"

# Проверка и подготовка SSL-ключей
SSL_CHECK_SCRIPT="${QUIC_PROXY_DIR}/scripts/cli/build/check_ssl.sh"
ensure_script_executable "$SSL_CHECK_SCRIPT"

printf "${YELLOW}🔐 Проверка и подготовка SSL-ключей для HTTP/3...${NC}\n" >&2
"$SSL_CHECK_SCRIPT" "$@"
if [[ $? -ne 0 ]]; then
    printf "${RED}❌ Ошибка при выполнении $SSL_CHECK_SCRIPT${NC}\n" >&2
    exit 1
fi

# Перезагружаем systemd (если требуется)
printf "${BLUE}▶️ Перезагружаем systemd daemon...${NC}\n" >&2
systemctl daemon-reload

# Включаем службу (запуск при загрузке)
printf "${GREEN}✅ Включаем службу quic-proxy (запуск при загрузке)...${NC}\n" >&2
systemctl enable quic-proxy.service || { printf "${RED}❌ Не удалось включить службу quic-proxy.service${NC}\n" >&2; exit 1; }

# Перезапускаем службу
restart_service "quic-proxy.service"

# Финальное сообщение
printf "${GREEN}✅ ✅ ✅ Установка и запуск завершены успешно! ✅ ✅ ✅${NC}\n" >&2