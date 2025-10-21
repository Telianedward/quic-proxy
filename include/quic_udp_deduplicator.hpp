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
        // Можно добавить другие поля, если нужно
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
     * @param token Токен из пакета.
     * @return true, если пакет повторный, false — иначе.
     */
    [[nodiscard]] bool is_duplicate(const ClientKey &key, const std::vector<uint8_t> &scid, const std::vector<uint8_t> &token) const;

    /**
     * @brief Удаляет информацию о соединении.
     * @param key Ключ клиента.
     */
    void remove_connection(const ClientKey &key);

private:
    std::unordered_map<ClientKey, PacketInfo, ClientKeyHash, ClientKeyEqual> packet_map_;
};