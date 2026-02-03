package pro.akosarev.sandbox;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Access Token - короткоживущий токен для доступа к ресурсам
 * Содержит полный набор authorities пользователя
 */
public record AccessToken(UUID id, String subject, List<String> authorities, Instant createdAt,
                          Instant expiresAt) {
}
