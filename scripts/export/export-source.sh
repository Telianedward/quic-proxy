#!/bin/bash
# ./export-source.sh

YELLOW='\e[33m'
GREEN='\e[32m'
RED='\e[31m'
NC='\e[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUTPUT_FILE="$SCRIPT_DIR/project-source.txt"

> "$OUTPUT_FILE"

printf "${YELLOW}🧱 Создаю файл $OUTPUT_FILE...${NC}\n"

FILES=(
    "main.cpp"
    "src/http3/quic_udp_proxy.cpp"
    "src/http3/quic_udp_deduplicator.cpp"
    "src/http3/client_key.cpp"
    "src/http2/tcp_proxy.cpp"
    "src/logger/logger.cpp"
    "include/http3/quic_udp_proxy.hpp"
    "include/http3/quic_udp_deduplicator.hpp"
    "include/http3/client_key.hpp"
    "include/http2/tcp_proxy.hpp"
    "CMakeLists.txt"
)

for file_path in "${FILES[@]}"; do
  full_path="$PROJECT_DIR/$file_path"
  if [ -f "$full_path" ]; then
    printf "${GREEN}✅ Добавляю: ${file_path}${NC}\n"

    # Пишем комментарий с путём — как часть кода
    printf "\n\n// \"%s\"\n" "$file_path" >> "$OUTPUT_FILE"

    # Копируем содержимое файла (с оригинальным @file)
    cat "$full_path" >> "$OUTPUT_FILE"
  else
    printf "${RED}❌ Файл не найден: ${file_path}${NC}\n"
  fi
done

printf "${YELLOW}🎉 Все указанные файлы объединены в $OUTPUT_FILE${NC}\n"