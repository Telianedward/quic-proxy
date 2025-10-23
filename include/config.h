/**
 * @file config.h
 * @brief Конфигурация приложения ErosJ.
 *
 * Содержит все параметры, необходимые для запуска HTTP/3 сервера:
 * - сетевые настройки,
 * - пути к сертификатам,
 * - домен,
 * - порты.
 *
 * Использует std::string_view для zero-overhead конфигурации.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-09-21
 * @version 1.0
 * @license MIT
 */
#pragma once

#include <string_view>

/**
 * @brief Структура для хранения всех настроек приложения.
 *
 * Все поля — статические constexpr string_view, безопасны для ODR.
 */
struct AppConfig {
    // === Общие настройки ===
    static constexpr std::string_view PROJECT_NAME = "ErosJ";
    // static constexpr std::string_view COMPANY_NAME = "ErosJ Design System";
    static constexpr std::string_view WIREGUARD_IP = "10.8.0.11";

    // // === Настройки безопасности и сети ===
    // static constexpr std::string_view HTTP3_PORT = "8585";
    // static constexpr std::string_view HTTP2_PORT = "8586";
    static constexpr std::string_view SSL_DIR = "/opt/quic-proxy"; // ✅ ИСПРАВЛЕНО
    static constexpr std::string_view DOMAIN = "erosj.com"; // ✅ ИСПРАВЛЕНО: должно быть доменом, а не "erosj-http3"

    // === Пути к сертификатам (внутри SSL_DIR) ===
    static constexpr std::string_view CERT_FILE  = "cert.pem";
    static constexpr std::string_view FULLCHAIN_FILE  = "fullchain.pem";
    static constexpr std::string_view PRIVEKEY_FILE = "privkey.pk8";
    static constexpr std::string_view KEY_FILE = "server.key";

    // === База данных (резерв) ===
    static constexpr std::string_view POSTGRESQL_HOST = "192.168.1.250";
    static constexpr std::string_view POSTGRESQL_PORT = "5432";
    static constexpr std::string_view POSTGRESQL_USER = "artel";
};