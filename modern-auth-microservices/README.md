# Modern Auth Microservices Project

Этот проект демонстрирует современную архитектуру аутентификации и авторизации с использованием Spring Boot 4.0.2, Java 22 и Keycloak.

## Структура проекта

- `server-auth`: Микросервис для регистрации и аутентификации пользователей. Взаимодействует с Keycloak для управления учетными записями.
- `resource-service`: Образец микросервиса ресурсов, который проверяет JWT и извлекает роли пользователей из токена.

## Технологический стек

- **Java**: 22
- **Spring Boot**: 4.0.2
- **Security**: Spring Security OAuth2 Resource Server
- **Identity Provider**: Keycloak 26.0.0
- **Build Tool**: Maven

## Запуск

### 1. Запуск Keycloak
Для работы проекта необходим запущенный Keycloak. Вы можете запустить его через Docker:
```bash
cd modern-auth-microservices
docker-compose up -d
```
После запуска:
- Админ-панель: `http://localhost:8080`
- Логин/пароль: `admin`/`admin`
- Необходимо создать Realm `sandbox-realm` и клиента `server-auth-client` с Access Type `public` (Standard Flow и Direct Access Grants включены).

### 2. Сборка и запуск микросервисов
```bash
cd server-auth
mvn clean install
mvn spring-boot:run

# В другом терминале
cd resource-service
mvn clean install
mvn spring-boot:run
```

## Тестирование
Используйте файл `tests.http` в корне проекта для выполнения запросов:
1. **Регистрация**: Создает нового пользователя в Keycloak.
2. **Логин**: Обменивает логин/пароль на JWT (Access & Refresh tokens).
3. **Доступ к ресурсам**: Демонстрирует авторизацию на основе ролей, извлеченных из JWT.
