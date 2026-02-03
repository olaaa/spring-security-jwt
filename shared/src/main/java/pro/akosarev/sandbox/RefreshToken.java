package pro.akosarev.sandbox;

import java.time.Instant;
import java.util.UUID;

/**
 * Refresh Token - долгоживущий токен для обновления Access Token
 * Содержит минимум информации: только subject и идентификатор
 * Не содержит authorities - они будут загружены из БД при обновлении
 */
public record RefreshToken(UUID id, String subject, Instant createdAt,
                           Instant expiresAt) {
}
