# Песочница Spring Security JWT

Этот проект демонстрирует различные стратегии аутентификации на основе JWT с использованием Spring Security 6 и Spring Boot 3. Он охватывает как распространенную аутентификацию "Bearer Token", так и более безопасную "Stateless Cookie" аутентификацию с использованием JWE (JSON Web Encryption).

## 🚀 Обзор

Репозиторий организован как многомодульный проект Maven:

- **`bearer-authentication`**: Реализация традиционной JWT-аутентификации, где токены передаются в заголовке `Authorization: Bearer <token>`. Включает поддержку Access и Refresh токенов.
- **`cookie-authentication`**: Реализация более безопасного подхода для SPA, использующего зашифрованные токены (JWE), хранящиеся в куках с флагами `HttpOnly`, `Secure` и префиксом `__Host-`.
- **`shared`**: Общие классы и утилиты, используемые обоими модулями аутентификации.

## 🛠 Технологический стек

- **Язык**: Java 21
- **Фреймворк**: Spring Boot 3.4.2 (Spring Security 6.4, Spring Data JDBC)
- **Безопасность**: Nimbus JOSE + JWT для работы с токенами (JWS/JWE)
- **База данных**: PostgreSQL
- **Контейнеризация**: Docker & Docker Compose
- **Инструмент сборки**: Maven

## 📋 Требования

- Java 21 или выше
- Maven 3.9+
- Docker и Docker Compose
- SSL-сертификат (Приложение настроено на работу через HTTPS. См. раздел [Конфигурация](#конфигурация)).

## 🚦 Быстрый старт

### 1. Настройка базы данных

Проект использует Docker Compose для управления базой данных PostgreSQL. Вы можете запустить её с помощью:

```bash
docker compose up -d
```

### 2. Конфигурация

#### SSL/TLS
Приложения по умолчанию настроены на использование HTTPS. Файлы `application.yml` ссылаются на локальное хранилище ключей:

```yaml
server:
  ssl:
    key-store: /path/to/your/keystore/localhost.p12
    key-store-password: password
    key-alias: localhost
```

**TODO**: Вам необходимо создать валидное хранилище ключей PKCS12 или обновить пути в `application.yml`, чтобы они указывали на ваш локальный сертификат.

#### JWT Ключи
Ключи, используемые для подписи и шифрования токенов, представлены в виде строк JWK (JSON Web Key) в `application.yml`. В рабочей среде их следует переместить в переменные окружения или защищенное хранилище секретов.

### 3. Запуск приложений

#### Модуль Bearer Authentication
```bash
mvn spring-boot:run -pl bearer-authentication
```
Точка входа: `pro.akosarev.sandbox.SandboxSpringSecurityJwtApplication`

#### Модуль Cookie Authentication
```bash
mvn spring-boot:run -pl cookie-authentication
```
Точка входа: `pro.akosarev.sandbox.SpaCookieAuthenticationApplication`

Приложения будут доступны по адресу `https://localhost:8443`.

## 📂 Структура проекта

```text
.
├── bearer-authentication/   # Реализация JWT Bearer токенов
├── cookie-authentication/   # Реализация JWT на основе кук (JWE)
├── shared/                  # Общие модели и логика безопасности
├── compose.yml              # Docker Compose для PostgreSQL
├── pom.xml                  # Родительский Maven POM
└── LICENSE                  # Лицензия MIT
```

## 📜 Эндпоинты

### Общие эндпоинты
- `POST /login`: Аутентификация и получение токенов (в заголовках или куках).
- `POST /logout`: Инвалидация текущей сессии/токена.

### Специфично для Cookie Auth
- `GET /csrf`: Получение CSRF-токена, необходимого для запросов, изменяющих состояние.

## 🧪 Тестирование

**TODO**: Автоматизированные тесты на данный момент не реализованы. Помощь в разработке приветствуется!

## 📄 Лицензия

Этот проект лицензирован на условиях MIT License — подробности см. в файле [LICENSE](LICENSE).

# 🎯 Зачем нужен TokenUser?
```
┌──────────────────────────────────────────────────────┐
│  1. Клиент отправляет Refresh Token                  │
└──────────────────────────────────────────────────────┘
↓
┌──────────────────────────────────────────────────────┐
│  2. JwtAuthenticationConverter                       │
│     - Парсит токен → RefreshToken объект             │
│     - Создает TokenUser с RefreshToken внутри        │
│     - Помещает в SecurityContext                     │
└──────────────────────────────────────────────────────┘
↓
┌──────────────────────────────────────────────────────┐
│  3. RefreshTokenFilter или JwtLogoutFilter           │
│     - Извлекает TokenUser из SecurityContext         │
│     - Достает RefreshToken из TokenUser              │
│     - Использует для бизнес-логики                   │
└──────────────────────────────────────────────────────┘
```