/**
 * @file logger.hpp
 * @brief Логгер для проекта на C++20/23 с поддержкой цветов и автоматического захвата контекста.
 *
 * Предоставляет удобный интерфейс для логирования с уровнями (DEBUG, INFO, WARN, ERROR, SUCCESS),
 * автоматическим добавлением файла, строки, функции и временной метки.
 * Поддерживает цветной вывод в терминале (ANSI escape codes) и эмодзи для визуального различения уровней.
 * Также предоставляет LOG_RAW для прямого вывода без контекста (например, для внешних библиотек).
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-09-29
 * @version 1.0
 * @license MIT
 */

#pragma once

#include <string>
#include <source_location>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <mutex>

#ifdef _WIN32
    #include <io.h>
    #include <fcntl.h>
#else
    #include <unistd.h>
#endif

/**
 * @brief Уровни логирования.
 */
enum class LogLevel {
    DEBUG,   ///< Отладочная информация (низкий приоритет)
    INFO,    ///< Общая информационная запись
    WARN,    ///< Предупреждение (возможная проблема)
    ERROR,   ///< Ошибка (нарушение нормального потока)
    SUCCESS  ///< Успешное завершение операции (визуально выделяется)
};

/**
 * @brief Внутреннее пространство имён для вспомогательных функций логгера.
 *
 * Все функции имеют внутреннюю линковку (static linkage) благодаря анонимному namespace.
 */
namespace {

/**
 * @brief Возвращает ANSI-код цвета для заданного уровня логирования.
 * @param level Уровень логирования.
 * @return Указатель на строку с ANSI-кодом цвета.
 */
const char* get_color_code(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:   return "\033[36m"; // Cyan
        case LogLevel::INFO:    return "\033[34m"; // Blue
        case LogLevel::WARN:    return "\033[33m"; // Yellow
        case LogLevel::ERROR:   return "\033[31m"; // Red
        case LogLevel::SUCCESS: return "\033[32m"; // Green
        default:                return "\033[0m";
    }
}

/**
 * @brief Возвращает эмодзи, соответствующий уровню логирования.
 * @param level Уровень логирования.
 * @return Указатель на строковый литерал с эмодзи в кодировке UTF-8.
 * @warning Требуется поддержка UTF-8 в терминале для корректного отображения.
 */
const char* get_emoji(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:   return "💟";
        case LogLevel::INFO:    return "🔵";
        case LogLevel::WARN:    return "⚠️";
        case LogLevel::ERROR:   return "❌";
        case LogLevel::SUCCESS: return "✅";
        default:                return "";
    }
}

/**
 * @brief ANSI-код для сброса цвета текста в терминале.
 */
const char* reset_color = "\033[0m";

/**
 * @brief Проверяет, является ли stdout терминалом.
 * @return true, если stdout подключён к TTY.
 */
bool is_stdout_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout));
#else
    return isatty(fileno(stdout));
#endif
}

/**
 * @brief Получает текущую временную метку в формате "ГГГГ-ММ-ДД ЧЧ:ММ:СС".
 * @return Строка с временной меткой в локальном часовом поясе.
 * @warning Использует std::localtime, который не является потокобезопасным в некоторых реализациях.
 *          Для многопоточных приложений рекомендуется использовать std::localtime_s (C11) или аналоги.
 */
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    // Потенциально небезопасно в многопоточной среде — см. предупреждение выше
    auto local_time = *std::localtime(&time_t);

    char buffer[20];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_time);
    return std::string(buffer);
}

// Глобальный мьютекс для потокобезопасности (опционально)
std::mutex log_mutex;

} // namespace

/**
 * @brief Основная шаблонная функция логирования с контекстом.
 *
 * Не вызывайте напрямую — используйте макросы LOG_DEBUG, LOG_INFO и т.д.
 *
 * @tparam Args Типы аргументов для форматирования.
 * @param level Уровень логирования.
 * @param file Имя исходного файла (обычно __FILE__).
 * @param line Номер строки (обычно __LINE__).
 * @param func Имя функции (обычно __func__).
 * @param format_str Строка формата (совместима с fmt::format или std::format).
 * @param args Аргументы для подстановки в строку формата.
 */
template<typename... Args>
void log_impl(LogLevel level,
              const char* file,
              int line,
              const char* func,
              const std::string& format_str,
              Args&&... args) {
    const bool use_color = is_stdout_tty();
    const char* color_start = use_color ? get_color_code(level) : "";
    const char* color_reset = use_color ? reset_color : "";

    const char* level_name = [&]() -> const char* {
        switch (level) {
            case LogLevel::DEBUG:   return "DEBUG";
            case LogLevel::INFO:    return "INFO";
            case LogLevel::WARN:    return "WARN";
            case LogLevel::ERROR:   return "ERROR";
            case LogLevel::SUCCESS: return "SUCCESS";
            default:                return "UNKNOWN";
        }
    }();

    // Форматируем сообщение
    std::string message = std::vformat(format_str, std::make_format_args(args...));

    // Блокировка мьютекса (опционально, если нужна потокобезопасность)
    std::lock_guard<std::mutex> lock(log_mutex);

    // Выводим в cerr
    std::cerr << color_start
              << "[" << get_timestamp() << "] "
              << get_emoji(level) << "[" << level_name << "] "
              << "[" << file << ":" << line << " in " << func << "] "
              << message
              << color_reset
              << std::endl;
}

/**
 * @brief Функция для "сырого" логирования без автоматического контекста.
 *
 * Используется для интеграции с внешними библиотеками (например, quiche),
 * которые передают готовые строки логов.
 *
 * @tparam Args Типы аргументов для форматирования.
 * @param format_str Строка формата.
 * @param args Аргументы для подстановки.
 */
template<typename... Args>
void log_raw_impl(const std::string& format_str, Args&&... args) {
    // Форматируем сообщение
    std::string message = std::vformat(format_str, std::make_format_args(args...));

    // Выводим в cerr
    std::cerr << message << std::endl;
}

/**
 * @brief Макрос для логирования уровня DEBUG.
 * @param ... Аргументы для форматирования (совместимы с std::format).
 */
#define LOG_DEBUG(...) log_impl(LogLevel::DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * @brief Макрос для логирования уровня INFO.
 * @param ... Аргументы для форматирования (совместимы с std::format).
 */
#define LOG_INFO(...)  log_impl(LogLevel::INFO,  __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * @brief Макрос для логирования уровня WARN.
 * @param ... Аргументы для форматирования (совместимы с std::format).
 */
#define LOG_WARN(...)  log_impl(LogLevel::WARN,  __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * @brief Макрос для логирования уровня ERROR.
 * @param ... Аргументы для форматирования (совместимы с std::format).
 */
#define LOG_ERROR(...) log_impl(LogLevel::ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * @brief Макрос для логирования уровня SUCCESS.
 * @param ... Аргументы для форматирования (совместимы с std::format).
 */
#define LOG_SUCCESS(...) log_impl(LogLevel::SUCCESS, __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * @brief Макрос для "сырого" логирования без контекста (время, файл, функция и т.д.).
 *
 * Используется, когда сообщение уже содержит всю необходимую информацию
 * или поступает из внешней библиотеки.
 *
 * @param ... Аргументы для форматирования (совместимы с std::format).
 * @warning Не добавляет временные метки, уровни или эмодзи — только то, что передано.
 */
#define LOG_RAW(...) log_raw_impl(__VA_ARGS__)