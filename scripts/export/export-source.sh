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
    "quic_udp_proxy.cpp"
    "quic_udp_proxy.hpp"
    "src/client_key.cpp"
    "src/quic_udp_deduplicator.cpp"
    "src/server/logger.cpp"
    "include/client_key.hpp"
    "include/quic_udp_deduplicator.hpp"
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