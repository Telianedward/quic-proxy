#!/bin/bash

# Убедитесь, что скрипт запущен с правами root (или через sudo)
if [ "$EUID" -ne 0 ]; then
    echo "Пожалуйста, запустите этот скрипт с правами root (sudo)."
    exit 1
fi

# Путь к каталогу
QUIC_PROXY_DIR="/opt/quic-proxy"



echo "=== Начинаем установку и запуск quic-proxy ==="

# 3. Переходим в каталог
cd "$QUIC_PROXY_DIR" || { echo "Не удалось перейти в каталог $QUIC_PROXY_DIR"; exit 1; }

rm -rf build

# 4. Создаём директорию сборки и собираем проект через CMake
echo "Создаём директорию сборки и собираем проект..."
mkdir -p build && cd build

# Запускаем CMake (устанавливаем стандарт C++23 и компилятор g++-12)
cmake .. -DCMAKE_CXX_COMPILER=g++-12 -DCMAKE_CXX_STANDARD=23

# Собираем проект
make -j$(nproc)

# Проверяем, успешно ли прошла компиляция
if [ $? -ne 0 ]; then
    echo "❌ Ошибка компиляции! Скрипт остановлен."
    exit 1
fi

# 5. Устанавливаем бинарник и сервис через CMake
echo "Устанавливаем бинарник и сервис..."
sudo make install

# # 6. Перезагружаем systemd
# echo "Перезагружаем systemd..."
# systemctl daemon-reload

# # 7. Включаем службу (запуск при загрузке)
# echo "Включаем службу quic-proxy..."
# systemctl enable quic-proxy.service

# # 8. Запускаем службу
# echo "Запускаем службу quic-proxy..."
# systemctl start quic-proxy.service

# 9. Перезапускаем службу (на всякий случай)
echo "Перезапускаем службу quic-proxy..."
systemctl restart quic-proxy.service

# # 10. Показываем статус службы
# echo "Статус службы quic-proxy:"
# systemctl status quic-proxy.service

# # 11. Показываем логи в реальном времени
# echo "=== Логи службы quic-proxy (Ctrl+C для выхода) ==="
# journalctl -u quic-proxy.service -f

echo "=== Установка и запуск завершены ==="