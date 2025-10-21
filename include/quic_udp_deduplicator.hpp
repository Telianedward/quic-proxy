/**
 * @file quic_udp_deduplicator.hpp
 * @brief Краткое описание назначения заголовочного файла.
 *
 * Более подробное описание того, какие классы, функции, структуры объявляет файл.
 * Может содержать информацию о зависимости от других модулей или ограничениях использования.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-21
 * @version 1.0
 * @license MIT
 */
// include/quic_udp_deduplicator.hpp
// include/quic_udp_deduplicator.hpp

#pragma once
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <string>
#include "client_key.hpp"

/**
 * @brief Класс для дедупликации QUIC-пакетов.
 *
 * Хранит информацию о первом Initial-пакете для каждого клиента.
 * Позволяет определить, является ли пакет повторным.
 */
class Deduplicator {
public:
    /**
     * @brief Структура для хранения информации о первом Initial-пакете.
     */
    struct PacketInfo {
        std::vector<uint8_t> token; ///< Токен из Retry-пакета
        std::vector<uint8_t> scid;  ///< SCID из первого Initial-пакета
        uint64_t packet_number;     ///< Номер пакета
        // Можно добавить другие поля, если нужно
    };

    /**
     * @brief Структура для ключа дедупликации.
     */
    struct PacketKey {
        ClientKey client_key;       ///< Ключ клиента (IP + порт)
        std::vector<uint8_t> scid;  ///< SCID
        std::vector<uint8_t> dcid;  ///< DCID
        uint64_t packet_number;     ///< Номер пакета
    };

    /**
     * @brief Хеш-функция для PacketKey.
     */
    struct PacketKeyHash {
        size_t operator()(const PacketKey &key) const noexcept;
    };

    /**
     * @brief Оператор сравнения для PacketKey.
     */
    struct PacketKeyEqual {
        bool operator()(const PacketKey &a, const PacketKey &b) const noexcept;
    };

    /**
     * @brief Конструктор.
     */
    Deduplicator() = default;

    /**
     * @brief Добавляет информацию о первом Initial-пакете.
     * @param key Ключ клиента.
     * @param info Информация о пакете.
     */
    void add_packet(const ClientKey &key, const PacketInfo &info);

    /**
     * @brief Проверяет, является ли пакет повторным.
     * @param key Ключ клиента.
     * @param scid SCID из пакета.
     * @param dcid DCID из пакета.
     * @param packet_number Номер пакета.
     * @return true, если пакет повторный, false — иначе.
     */
    [[nodiscard]] bool is_duplicate(const ClientKey &key, const std::vector<uint8_t> &scid, const std::vector<uint8_t> &dcid, uint64_t packet_number) const;

    /**
     * @brief Удаляет информацию о соединении.
     * @param key Ключ клиента.
     */
    void remove_connection(const ClientKey &key);

private:
    std::unordered_map<PacketKey, bool, PacketKeyHash, PacketKeyEqual> seen_packets_;
};