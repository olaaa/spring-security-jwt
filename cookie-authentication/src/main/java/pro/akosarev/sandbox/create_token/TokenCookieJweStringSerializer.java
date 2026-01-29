package pro.akosarev.sandbox.create_token;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.akosarev.sandbox.Token;

import java.util.Date;
import java.util.function.Function;

/**
 * Сериализатор объекта {@link Token} в зашифрованную строку JWE.
 *
 * <p>Этот класс превращает Java-объект токена в компактную зашифрованную строку, которую
 * можно безопасно передать клиенту через куки. Используется стандарт JWE (JSON Web Encryption),
 * что гарантирует конфиденциальность данных: никто, кроме сервера, не может прочитать содержимое токена.</p>
 */
public class TokenCookieJweStringSerializer implements Function<Token, String> {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenCookieJweStringSerializer.class);

    private final JWEEncrypter jweEncrypter;

    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;

    private EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;

    /**
     * Конструктор сериализатора с алгоритмами по умолчанию (DIR и A128GCM).
     *
     * @param jweEncrypter объект для шифрования JWE
     */
    public TokenCookieJweStringSerializer(JWEEncrypter jweEncrypter) {
        this.jweEncrypter = jweEncrypter;
    }

    /**
     * Конструктор сериализатора с возможностью указания алгоритмов.
     *
     * @param jweEncrypter     объект для шифрования JWE
     * @param jweAlgorithm     алгоритм JWE
     * @param encryptionMethod метод шифрования
     */
    public TokenCookieJweStringSerializer(JWEEncrypter jweEncrypter, JWEAlgorithm jweAlgorithm, EncryptionMethod encryptionMethod) {
        this.jweEncrypter = jweEncrypter;
        this.jweAlgorithm = jweAlgorithm;
        this.encryptionMethod = encryptionMethod;
    }

    /**
     * Сериализует объект Token в зашифрованную строку JWE.
     *
     * @param token объект токена
     * @return зашифрованная строка JWE или null в случае ошибки шифрования
     */
    @Override
    public String apply(Token token) {
        var jwsHeader = new JWEHeader.Builder(this.jweAlgorithm, this.encryptionMethod)
                .keyID(token.id().toString())
                .build();
        var claimsSet = new JWTClaimsSet.Builder()
                .jwtID(token.id().toString())
                .subject(token.subject())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim("authorities", token.authorities())
                .build();
        var encryptedJWT = new EncryptedJWT(jwsHeader, claimsSet);
        try {
            encryptedJWT.encrypt(this.jweEncrypter);

            return encryptedJWT.serialize();
        } catch (JOSEException exception) {
            LOGGER.error(exception.getMessage(), exception);
        }

        return null;
    }

    /**
     * Устанавливает алгоритм JWE.
     *
     * @param jweAlgorithm алгоритм JWE
     */
    public void setJweAlgorithm(JWEAlgorithm jweAlgorithm) {
        this.jweAlgorithm = jweAlgorithm;
    }

    /**
     * Устанавливает метод шифрования.
     *
     * @param encryptionMethod метод шифрования
     */
    public void setEncryptionMethod(EncryptionMethod encryptionMethod) {
        this.encryptionMethod = encryptionMethod;
    }
}
