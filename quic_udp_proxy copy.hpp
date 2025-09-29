// /**
//  * @file async_http3_server.h
//  * @brief Асинхронный HTTP/3 сервер на quiche.
//  *
//  * Реализует настоящий QUIC end-to-end.
//  * Поддерживает: H3, ALPN, embedded ресурсы, favicon.
//  *
//  * @author Telian Edward <telianedward@icloud.com>
//  * @assisted-by AI-Assistant
//  * @date 2025-09-10
//  * @version 1.0
//  * @license MIT
//  */

// #pragma once
// #ifndef ASYNC_HTTP3_SERVER_H
// #define ASYNC_HTTP3_SERVER_H

// #include <netinet/in.h>
// #include <string>
// #include <unordered_map>
// #include <vector>
// #include <atomic>
// #include <cstddef>   // Для nullptr
// #include <cstdint>   // Для uint8_t

// // C-заголовки (внешние)
// extern "C" {
// #include <quiche.h>
// }

// extern "C" {
//     int quiche_config_load_priv_key(quiche_config *config,
//                                     const uint8_t *key_pem, size_t key_pem_len);
// }

// namespace OnlyWhim {

// /**
//  * @brief Класс для асинхронного HTTP/3 сервера на основе quiche.
//  *
//  * Обрабатывает QUIC-пакеты, создаёт H3-соединения,
//  * генерирует ответы через ContentHandler.
//  */
// class AsyncHttp3Server {
// public:
//     /**
//      * @brief Конструктор сервера.
//      * @param port Порт, на котором будет слушать сервер (по умолчанию 443).
//      */
//     explicit AsyncHttp3Server(int port = 443);

//     /**
//      * @brief Деструктор.
//      * Освобождает ресурсы: закрывает сокет, освобождает quiche-конфигурации.
//      */
//     ~AsyncHttp3Server();

//     /**
//      * @brief Запускает сервер в цикле ожидания пакетов.
//      * @return true, если сервер успешно запущен и работает.
//      */
//     bool run();

//     /**
//      * @brief Останавливает сервер.
//      */
//     void stop();

// private:
//     int port_;                            ///< Порт сервера
//     int udp_fd_;                          ///< Дескриптор UDP-сокета
//     quiche_config* config_;               ///< Конфигурация QUIC
//     quiche_h3_config* h3_config_;         ///< Конфигурация HTTP/3
//     struct sockaddr_in server_addr_;      ///< Адрес сервера
//     std::unordered_map<std::string, quiche_conn*> connections_;  ///< Маппинг ключа → QUIC-соединение
//     std::unordered_map<std::string, quiche_h3_conn*> h3_connections_; ///< Маппинг ключа → H3-соединение
//     std::atomic<bool> running_{false};    ///< Флаг работы сервера

//     /**
//      * @brief Генерирует уникальный ключ соединения на основе адреса клиента и DCID.
//      * @param addr Адрес клиента.
//      * @return Строка-ключ для маппинга соединения.
//      */
//     std::string generate_key(const sockaddr_in& addr);

//     /**
//      * @brief Обрабатывает входящие данные от клиента.
//      * @param client_addr Адрес клиента.
//      * @param buf Буфер с данными.
//      * @param len Длина данных.
//      */
//     void handle_client_data(sockaddr_in client_addr, const char* buf, ssize_t len);

//     /**
//      * @brief Собирает заголовки из H3-пакета.
//      * @param name Имя заголовка.
//      * @param name_len Длина имени.
//      * @param value Значение заголовка.
//      * @param value_len Длина значения.
//      * @param arg Указатель на вектор пар (имя, значение).
//      * @return 0 — успех.
//      */
//     static int collect_headers(uint8_t* name, size_t name_len,
//                                uint8_t* value, size_t value_len,
//                                void* arg);

//     /**
//      * @brief Генерирует HTML-ответ на основе пути запроса.
//      * @param path Путь запроса (например, "/index.html").
//      * @return Строка с HTML-контентом.
//      */
//     std::string generate_response(const std::string& path);
// };

// } // namespace OnlyWhim

// #endif // ASYNC_HTTP3_SERVER_H