Вот примеры запросов на `/login` и сравнение с Basic аутентификацией:

## 1. Form Login - Запрос через форму

### GET `/login` - Получение формы входа
```
GET https://localhost:8443/login
Accept: text/html
```


**Ответ:** HTML-страница с формой входа
```html
<!DOCTYPE html>
<html>
<head>
    <title>Login Page</title>
</head>
<body>
    <form method="post" action="/login">
        <input type="hidden" name="_csrf" value="abc123..."/>
        <label>Username: <input type="text" name="username"/></label>
        <label>Password: <input type="password" name="password"/></label>
        <button type="submit">Login</button>
    </form>
</body>
</html>
```


### POST `/login` - Отправка данных формы
```
POST https://localhost:8443/login
Content-Type: application/x-www-form-urlencoded
Cookie: XSRF-TOKEN=abc123...

username=j.jameson&password=password&_csrf=abc123...
```


**Ответ при успехе:**
```
HTTP/1.1 302 Found
Location: /
Set-Cookie: __Host-auth-token=eyJ...; HttpOnly; Secure; SameSite=Strict
Set-Cookie: XSRF-TOKEN=xyz789...; Secure; SameSite=Strict
```


## 2. Basic Authentication - Запрос с заголовком

```
GET https://localhost:8443/api/greetings
Authorization: Basic ai5qYW1lc29uOnBhc3N3b3Jk
```


**Ответ при успехе:**
```
HTTP/1.1 200 OK
Set-Cookie: __Host-auth-token=eyJ...; HttpOnly; Secure
Set-Cookie: XSRF-TOKEN=xyz789...; Secure

{"greeting": "Hello, j.jameson!"}
```


## Основные отличия

| Характеристика | Form Login | Basic Authentication |
|---|---|---|
| **Метод передачи** | POST форма с полями `username`, `password`, `_csrf` | HTTP заголовок `Authorization: Basic base64(username:password)` |
| **Количество запросов** | 2 запроса (GET форму → POST данные) | 1 запрос |
| **CSRF защита** | ✅ Требует CSRF токен | ❌ Не использует CSRF |
| **UI/UX** | ✅ Настраиваемая HTML форма | ❌ Браузерный диалог (некрасивый) |
| **Безопасность** | ✅ Данные в теле POST-запроса | ⚠️ Данные в заголовке (видны в логах) |
| **Кэширование браузера** | ❌ Не кэшируется | ⚠️ Браузер может кэшировать учетные данные |
| **Контроль над процессом** | ✅ Полный контроль (redirect, ошибки) | ❌ Ограниченный контроль |
| **Совместимость с SPA** | ⚠️ Требует обработки редиректов | ✅ Простое использование в AJAX |
| **Logout** | ✅ Явный POST `/logout` с CSRF | ❌ Нет стандартного способа |

## В вашем приложении

Поскольку у вас настроены **оба метода**, клиент может использовать любой:

1. **Браузер/SPA** может использовать форму для красивого UI
2. **API клиенты** могут использовать Basic Auth для простоты
3. **Последующие запросы** используют cookie с токеном (одинаково для обоих методов)

Это делает ваше приложение гибким для разных типов клиентов.