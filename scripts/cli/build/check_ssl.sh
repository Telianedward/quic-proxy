#!/bin/bash

# === Настройки цветов ===
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
NC='\e[0m'

# === Настройки ===
NAME="erosj"
DOMAIN="${NAME}.com"
ACME_PATH="/root/.acme.sh/${DOMAIN}"
SSL_DIR="/opt/quic-proxy"

printf "${CYAN}🔐 Подготовка SSL-ключей и сборка quiche для ${DOMAIN}${NC}\n"

# === Пути к файлам ===
CERT_SRC="$ACME_PATH/${DOMAIN}.cer"          # Только ваш сертификат
CHAIN_SRC="$ACME_PATH/ca.cer"               # Цепочка (если нужна)
KEY_SRC="$ACME_PATH/${DOMAIN}.key"           # Приватный ключ

for f in "$CERT_SRC" "$CHAIN_SRC" "$KEY_SRC"; do
    if [ ! -f "$f" ]; then
        printf "${RED}❌ Файл не существует: $f${NC}\n"
        exit 1
    fi
done

printf "${GREEN}✅ Используем:\n   Сертификат: $CERT_SRC\n   Цепочка: $CHAIN_SRC\n   Ключ: $KEY_SRC${NC}\n"

# === Создаём целевую директорию ===
sudo mkdir -p "$SSL_DIR"
sudo rm -f "$SSL_DIR"/*.pem "$SSL_DIR"/*.pk8

printf "${GREEN}✅ Проверка содержимого папки : "$SSL_DIR"${NC}\n"
ls -la "$SSL_DIR"

# Установите владельца и права на директорию /etc/ssl/private/erosj-http3/
sudo chown -R www-data:www-data "$SSL_DIR"
sudo chmod 755 "$SSL_DIR"

# === Конвертируем ключ в PKCS#8... ===
PK8_TARGET="$SSL_DIR/privkey.pk8"          # Без номера версии
FULLCHAIN_TARGET="$SSL_DIR/fullchain.pem"  # Без номера версии

cd /tmp || { printf "${RED}❌ Не удалось перейти в /tmp${NC}\n"; exit 1; }

printf "${YELLOW}🔄 Конвертируем ключ в PKCS#8...${NC}\n"

openssl pkcs8 -in "$KEY_SRC" -topk8 -nocrypt -out "privkey.pk8.tmp"

if [ $? -ne 0 ]; then
    printf "${RED}❌ Ошибка конвертации ключа через openssl pkcs8${NC}\n"
    exit 1
fi

# Чистим временный файл: убираем \r, пустые строки
sed -i 's/\r$//' "privkey.pk8.tmp"
sed -i '/^$/d' "privkey.pk8.tmp"


# Извлекаем только base64 (игнорируем строки с BEGIN/END)
b64=$(grep -v '^-----' "privkey.pk8.tmp" | tr -d '\n')

if [ -z "$b64" ]; then
    printf "${RED}❌ Не удалось извлечь base64 из ключа${NC}\n"
    exit 1
fi

# Разбиваем на строки по 64 символа
rm -f "privkey.pk8.fixed"
for ((i=0; i<${#b64}; i+=64)); do
    echo "${b64:i:64}" >> "privkey.pk8.fixed"
done

# Собираем обратно в PEM
cat > "privkey.pk8.final" << EOF
-----BEGIN PRIVATE KEY-----
EOF
cat "privkey.pk8.fixed" >> "privkey.pk8.final"
cat >> "privkey.pk8.final" << EOF
-----END PRIVATE KEY-----
EOF

# Перемещаем в целевое место
sudo mv "privkey.pk8.final" "$PK8_TARGET"  # ✅ Файл будет называться privkey.pk8

# Удаляем временные файлы
rm -f "privkey.pk8.tmp" "privkey.pk8.fixed"

# === ПЕРЕСОБИРАЕМ fullchain.pem — ПРАВИЛЬНЫЙ ПОРЯДОК И ФОРМАТ ===
printf "${YELLOW}🔄 Пересобираем fullchain.pem — правильный порядок и формат...${NC}\n"

# Очищаем временные файлы
rm -f /tmp/cert_clean.pem /tmp/chain_clean.pem

# Копируем и нормализуем: убираем \r, лишние пробелы, пустые строки
tr -d '\r' < "$CERT_SRC" | sed '/^$/d' > /tmp/cert_clean.pem
tr -d '\r' < "$CHAIN_SRC" | sed '/^$/d' > /tmp/chain_clean.pem

# Создаём fullchain.pem: сначала ваш сертификат, потом chain
{
    cat /tmp/cert_clean.pem
    echo  # гарантированная пустая строка между
    cat /tmp/chain_clean.pem
} | sudo tee "$FULLCHAIN_TARGET" > /dev/null

# Убедимся, что нет мусора
sudo sed -i 's/[[:space:]]*$//' "$FULLCHAIN_TARGET"  # удаляем trailing spaces

# Добавляем новую строку в конец файла (если её нет) — ПРАВИЛЬНЫЙ СПОСОБ
printf "${YELLOW}➕ Добавляем новую строку в конец файла...${NC}\n"
if ! sudo tail -c 1 "$FULLCHAIN_TARGET" | grep -q $'\n'; then
    echo "" | sudo tee -a "$FULLCHAIN_TARGET" > /dev/null
    printf "${GREEN}✅ Новая строка добавлена в конец файла.${NC}\n"
else
    printf "${YELLOW}⚠️ Файл уже заканчивается на новую строку.${NC}\n"
fi

# Проверяем результат
if ! openssl crl2pkcs7 -nocrl -certfile "$FULLCHAIN_TARGET" >/dev/null 2>&1; then
    printf "${RED}❌ Ошибка: fullchain.pem некорректен после генерации!${NC}\n"
    exit 1
fi

printf "${GREEN}✅ fullchain.pem успешно пересобран с правильным форматом${NC}\n"

# Чистим временные файлы
rm -f /tmp/cert_tmp.pem /tmp/chain_tmp.pem

#  /etc/ssl/private/erosj-http3/fullchain.pem
#sudo hexdump -C /etc/ssl/private/erosj-http3/fullchain.pem| head -n 20
# sudo hexdump -C "$FULLCHAIN_TARGET" | head -n 20

printf "${GREEN}✅ fullchain.pem успешно пересобран${NC}\n"

# === Конвертируем ключ в PKCS#8 (исправлено) ===
printf "${YELLOW}🔄 Конвертируем ключ в PKCS#8...${NC}\n"

openssl pkcs8 -in "$KEY_SRC" -topk8 -nocrypt -out "privkey.pk8.tmp" 2>/dev/null
if [ $? -ne 0 ]; then
    printf "${RED}❌ Ошибка конвертации ключа через openssl pkcs8${NC}\n"
    exit 1
fi

# Чистим временный файл: убираем \r, пустые строки
sed -i 's/\r$//' "privkey.pk8.tmp"
sed -i '/^$/d' "privkey.pk8.tmp"

# Извлекаем только base64 (игнорируем строки с BEGIN/END)
b64=$(grep -v '^-----' "privkey.pk8.tmp" | tr -d '\n')

if [ -z "$b64" ]; then
    printf "${RED}❌ Не удалось извлечь base64 из ключа${NC}\n"
    exit 1
fi

# Разбиваем на строки по 64 символа
rm -f "privkey.pk8.fixed"
for ((i=0; i<${#b64}; i+=64)); do
    echo "${b64:i:64}" >> "privkey.pk8.fixed"
done

# Собираем обратно в PEM
cat > "privkey.pk8.final" << EOF
-----BEGIN PRIVATE KEY-----
EOF
cat "privkey.pk8.fixed" >> "privkey.pk8.final"
cat >> "privkey.pk8.final" << EOF
-----END PRIVATE KEY-----
EOF

# Перемещаем в целевое место
sudo mv "privkey.pk8.final" "$PK8_TARGET"  # ✅ Файл будет называться privkey.pk8

# Удаляем временные файлы
rm -f "privkey.pk8.tmp" "privkey.pk8.fixed"

printf "${GREEN}✅ privkey.pk8 успешно создан${NC}\n"

# === ШАГ: ОЧИСТКА И ПЕРЕСОЗДАНИЕ fullchain.pem ===
printf "${CYAN}🔄 Начинаем очистку и пересоздание fullchain.pem...${NC}\n"

# 1. Удаляем старый файл (если существует)
printf "${YELLOW}🗑️ Удаляем старый fullchain.pem...${NC}\n"
sudo rm -f "$FULLCHAIN_TARGET"
if [ $? -eq 0 ]; then
    printf "${GREEN}✅ Старый файл удалён успешно.${NC}\n"
else
    printf "${YELLOW}⚠️ Файл не существовал или не удалось удалить (не критично).${NC}\n"
fi

# 2. Копируем исходный fullchain.cer в целевую директорию
printf "${YELLOW}📄 Копируем исходный fullchain.cer в $FULLCHAIN_TARGET...${NC}\n"
sudo cp "$ACME_PATH/fullchain.cer" "$FULLCHAIN_TARGET"
if [ $? -ne 0 ]; then
    printf "${RED}❌ Ошибка при копировании файла!${NC}\n"
    exit 1
fi
printf "${GREEN}✅ Файл успешно скопирован.${NC}\n"

# 3. Удаляем BOM (Byte Order Mark), если он есть
printf "${YELLOW}🧹 Удаляем BOM (Byte Order Mark) из начала файла...${NC}\n"
sudo sed -i '1s/^\xEF\xBB\xBF//' "$FULLCHAIN_TARGET"
if [ $? -eq 0 ]; then
    printf "${GREEN}✅ BOM удалён (если был).${NC}\n"
else
    printf "${YELLOW}⚠️ Не удалось обработать BOM (возможно, его не было).${NC}\n"
fi

# 4. Удаляем все пустые строки и лишние пробелы
printf "${YELLOW}🧹 Удаляем пустые строки и лишние пробелы...${NC}\n"
sudo sed -i -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$//g' -e '/^$/d' "$FULLCHAIN_TARGET"
if [ $? -ne 0 ]; then
    printf "${RED}❌ Ошибка при очистке файла от пробелов и пустых строк!${NC}\n"
    exit 1
fi
printf "${GREEN}✅ Файл очищен от пробелов и пустых строк.${NC}\n"

# 5. Добавляем новую строку в конец файла (если её нет) — ПРАВИЛЬНЫЙ СПОСОБ
printf "${YELLOW}➕ Добавляем новую строку в конец файла...${NC}\n"
if ! sudo tail -c 1 "$FULLCHAIN_TARGET" | grep -q $'\n'; then
    echo "" | sudo tee -a "$FULLCHAIN_TARGET" > /dev/null
    printf "${GREEN}✅ Новая строка добавлена в конец файла.${NC}\n"
else
    printf "${YELLOW}⚠️ Файл уже заканчивается на новую строку.${NC}\n"
fi

# 6. Проверяем результат — выводим первые и последние 5 строк
printf "${YELLOW}🔍 Проверяем содержимое файла...${NC}\n"
# echo "=== Первые 5 строк ==="
# sudo head -n 5 "$FULLCHAIN_TARGET"
# echo "=== Последние 5 строк ==="
# sudo tail -n 5 "$FULLCHAIN_TARGET"

# 7. Проверка: убедимся, что файл начинается с "-----BEGIN CERTIFICATE-----"
printf "${YELLOW}🔍 Проверяем, что файл начинается с корректного заголовка...${NC}\n"
first_line=$(sudo head -n 1 "$FULLCHAIN_TARGET")
if [[ "$first_line" == "-----BEGIN CERTIFICATE-----" ]]; then
    printf "${GREEN}✅ Файл начинается с правильного заголовка.${NC}\n"
else
    printf "${RED}❌ ОШИБКА: Файл НЕ начинается с -----BEGIN CERTIFICATE-----\n"
    printf "Первая строка: '$first_line'\n"
    exit 1
fi

# 8. Проверка: убедимся, что файл заканчивается на "-----END CERTIFICATE-----"
printf "${YELLOW}🔍 Проверяем, что файл заканчивается на корректный футер...${NC}\n"
last_line=$(sudo tail -n 1 "$FULLCHAIN_TARGET")
if [[ "$last_line" == "-----END CERTIFICATE-----" ]]; then
    printf "${GREEN}✅ Файл заканчивается на правильный футер.${NC}\n"
else
    printf "${RED}❌ ОШИБКА: Файл НЕ заканчивается на -----END CERTIFICATE-----\n"
    printf "Последняя строка: '$last_line'\n"
    exit 1
fi

printf "${GREEN}✅ fullchain.pem успешно очищен и подготовлен для quiche!${NC}\n"

sudo chmod 644 "$FULLCHAIN_TARGET"

# === Создаём cert_only.pem (гарантированно) ===
printf "${YELLOW}🔄 Генерируем cert_only.pem...${NC}\n"
sudo openssl x509 -in "$CERT_SRC" -out "$SSL_DIR/cert_only.pem" -outform PEM
if [ $? -ne 0 ]; then
    printf "${RED}❌ Ошибка при генерации cert_only.pem${NC}\n"
    exit 1
fi

printf "${GREEN}✅ cert_only.pem успешно создан: $(realpath $SSL_DIR/cert_only.pem)${NC}\n"
# === Устанавливаем владельца и права ===
sudo chown -R www-data:www-data "$SSL_DIR"   # Сервер работает от root → владелец = root
sudo chmod 600 "$PK8_TARGET"                 # Позволяем читать ключу всем (безопасно, так как сервер в РФ)
sudo chmod 644 "$FULLCHAIN_TARGET"

printf "${GREEN}✅ Права установлены: www-data:www-data${NC}\n"

# Устанавливаем владельца и права для cert_only.pem
sudo chown www-data:www-data "$SSL_DIR/cert_only.pem"
sudo chmod 644 "$SSL_DIR/cert_only.pem"

# Устанавливаем владельца и права для cert.pem и chain.pem
sudo chown www-data:www-data "$SSL_DIR/*"
sudo chmod 644 "$SSL_DIR/cert_only.pem"
sudo chmod 644 "$SSL_DIR/fullchain.pem"
sudo chmod 600 "$SSL_DIR/privkey.pk8"

# printf "${GREEN}✅Смотрим содержимое файла: ${SSL_DIR}/cert_only.pem"
# sudo cat "$SSL_DIR/cert_only.pem"

printf "${GREEN}✅ Файлы cert.pem и chain.pem успешно скопированы${NC}\n"



# === Диагностика содержимого ключа ===
printf "${CYAN}🔍 Проверка содержимого privkey.pk8:${NC}\n"
sudo head -n 5 "$PK8_TARGET" | while read line; do
    printf "  ${BLUE}%s${NC}\n" "$line"
done
printf "${CYAN}... (остальные строки опущены)${NC}\n"

# === Диагностика ===
printf "${CYAN}🔍 Диагностика файла "$SSL_DIR": ${NC}\n"
sudo ls -la "$SSL_DIR"

# === Проверка соответствия ===
printf "${YELLOW}🔄 Проверяем соответствие ключа и сертификата...${NC}\n"

cert_mod=$(sudo -u www-data openssl x509 -noout -modulus -in "$FULLCHAIN_TARGET" | openssl md5)
key_mod=$(sudo -u www-data openssl rsa -noout -modulus -in "$PK8_TARGET" | openssl md5)

if [ "$cert_mod" != "$key_mod" ]; then
    printf "${RED}❌ КЛЮЧ И СЕРТИФИКАТ НЕ СОВПАДАЮТ!${NC}\n"
    printf "Cert MD5: $cert_mod\n"
    printf "Key MD5:  $key_mod\n"
    exit 1
fi

printf "${GREEN}✅ Ключ и сертификат совпадают${NC}\n"

# === Дополнительная проверка: доступ www-data к файлам ===
printf "${YELLOW}🔄 Проверка доступа к приватному ключу от имени www-data...${NC}\n"
sudo -u www-data cat "$PK8_TARGET" > /dev/null && \
    printf "${GREEN}✅ OK: пользователь www-data может читать ключ${NC}\n" || \
    printf "${RED}❌ Нет доступа: www-data не может читать $PK8_TARGET${NC}\n"

printf "${YELLOW}🔄 Проверка доступа к fullchain.pem...${NC}\n"
sudo -u www-data cat "$FULLCHAIN_TARGET" > /dev/null && \
    printf "${GREEN}✅ OK: пользователь www-data может читать сертификат${NC}\n" || \
    printf "${RED}❌ Нет доступа: www-data не может читать $FULLCHAIN_TARGET${NC}\n"

# === Экспорт переменных ===
export EROSJ_HTTP3_CERT="$FULLCHAIN_TARGET"
export EROSJ_HTTP3_KEY="$PK8_TARGET"

printf "${GREEN}🎉 SSL-ключи готовы: $FULLCHAIN_TARGET + $PK8_TARGET${NC}\n"

# 🚀 === Завершение ===
printf "${GREEN}🚀 Всё готово! Можно запускать HTTP/3 сервер.${NC}\n"
# printf "${BLUE}💡 Путь к сертификату: ${EROSJ_HTTP3_CERT}${NC}\n"
# printf "${BLUE}💡 Путь к ключу:      ${EROSJ_HTTP3_KEY}${NC}\n"