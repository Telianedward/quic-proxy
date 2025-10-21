#!/bin/bash

# Убедитесь, что скрипт запущен с правами root (или через sudo)
if [ "$EUID" -ne 0 ]; then
    echo "Пожалуйста, запустите этот скрипт с правами root (sudo)."
    exit 1
fi

# Путь к каталогу
QUIC_PROXY_DIR="/opt/quic-proxy"

echo "=== Начинаем установку и запуск quic-proxy ==="

# 1. Удаляем старую версию (если есть)
echo "Удаляем предыдущую версию..."
rm -rf "$QUIC_PROXY_DIR"

# 2. Клонируем репозиторий
echo "Клонируем репозиторий..."
git clone https://github.com/Telianedward/quic-proxy.git "$QUIC_PROXY_DIR"

# 3. Проверяем наличие build.sh
BUILD_SCRIPT="$QUIC_PROXY_DIR/scripts/build.sh"
if [ ! -f "$BUILD_SCRIPT" ]; then
    echo "❌ Файл $BUILD_SCRIPT не найден в репозитории!"
    exit 1
fi

# 4. Даем права на выполнение
echo "Даём права на выполнение build.sh..."
chmod +x "$BUILD_SCRIPT"

# 5. Запускаем build.sh
echo "Запускаем build.sh..."
"$BUILD_SCRIPT"

# 6. Выводим сообщение о завершении
echo "=== Установка и запуск завершены ==="
