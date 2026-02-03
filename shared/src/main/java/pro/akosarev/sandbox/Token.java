package pro.akosarev.sandbox;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

// один класс для access и refresh токенов
// String subject имя пользователя
public record Token(UUID id, String subject, List<String> authorities, Instant createdAt,
                    Instant expiresAt) {
}
