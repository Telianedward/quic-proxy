#!/bin/bash

# Цвета
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
NC='\e[0m' #  # No Color


printf "${CYAN}✅  🇷🇺 ⚠️ 💀 Запуск файла scripts/build.sh 💀 ⚠️ 🇷🇺 ✅ ${NC}\n"
# Убедитесь, что скрипт запущен с правами root (или через sudo)
if [ "$EUID" -ne 0 ]; then
printf "${RED}  ❌ 💀 Пожалуйста, запустите этот скрипт с правами root (sudo). 💀${NC}\n"
    exit 1
fi

# Путь к каталогу
QUIC_PROXY_DIR="/opt/quic-proxy"

printf "${GREEN}✅  Начинаем установку и запуск quic-proxy... ${NC}\n"


# 3. Переходим в каталог
cd "$QUIC_PROXY_DIR" || { printf "${RED}  ❌ Не удалось перейти в каталог $QUIC_PROXY_DIR${NC}\n"; exit 1; }


rm -rf build

# 4. Создаём директорию сборки и собираем проект через CMake
printf "${GREEN}✅  Создаём директорию сборки и собираем проект... ${NC}\n"
mkdir -p build && cd build

# Запускаем CMake (устанавливаем стандарт C++23 и компилятор g++-12)
cmake .. -DCMAKE_CXX_COMPILER=g++-12 -DCMAKE_CXX_STANDARD=23

# Собираем проект
make -j$(nproc)

# Проверяем, успешно ли прошла компиляция
if [ $? -ne 0 ]; then
    echo "${RED} ❌ Ошибка компиляции! Скрипт остановлен.${NC}\n"
    exit 1
fi

# 5. Устанавливаем бинарник и сервис через CMake
printf "${GREEN}✅  Устанавливаем бинарник и сервис... ${NC}\n"
sudo make install

sudo cp /root/.acme.sh/erosj.com_ecc/erosj.com.cer /opt/quic-proxy/server.crt
sudo cp /root/.acme.sh/erosj.com_ecc/erosj.com.key /opt/quic-proxy/server.key


sudo chown root:root /opt/quic-proxy/server.*
sudo chmod 600 /opt/quic-proxy/server.key  # Ключ должен быть защищён
sudo chmod 644 /opt/quic-proxy/server.crt  # Сертификат можно читать всем
# # 6. Перезагружаем systemd
# echo "Перезагружаем systemd..."
# systemctl daemon-reload

printf "${GREEN}✅  Проверяем ключи ... ${NC}\n"
ls -la /opt/quic-proxy/server.crt
ls -la /opt/quic-proxy/server.key
# # 7. Включаем службу (запуск при загрузке)
# echo "Включаем службу quic-proxy..."
# systemctl enable quic-proxy.service

# # 8. Запускаем службу
# echo "Запускаем службу quic-proxy..."
# systemctl start quic-proxy.service

# 9. Перезапускаем службу (на всякий случай)
printf "${GREEN}✅  Перезапускаем службу quic-proxy... ${NC}\n"
systemctl restart quic-proxy.service

# # 10. Показываем статус службы
# echo "Статус службы quic-proxy:"
# systemctl status quic-proxy.service

# # 11. Показываем логи в реальном времени
# echo "=== Логи службы quic-proxy (Ctrl+C для выхода) ==="
# journalctl -u quic-proxy.service -f
printf "${GREEN}✅ ✅ ✅  Установка и запуск завершены  ✅ ✅ ✅  ${NC}\n"