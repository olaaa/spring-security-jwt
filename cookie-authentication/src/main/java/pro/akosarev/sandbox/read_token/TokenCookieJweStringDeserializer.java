package pro.akosarev.sandbox.read_token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.akosarev.sandbox.Token;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

/**
 * Десериализатор зашифрованной JWE строки в объект {@link Token}.
 *
 * <p>Класс выполняет обратное преобразование: получает зашифрованную строку из куки,
 * расшифровывает её с помощью приватного ключа сервера и восстанавливает объект {@link Token}.
 * Если строка повреждена или зашифрована чужим ключом, расшифровка завершится ошибкой,
 * что защищает приложение от поддельных токенов.</p>
 */
public class TokenCookieJweStringDeserializer implements Function<String, Token> {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenCookieJweStringDeserializer.class);

    private final JWEDecrypter jweDecrypter;

    /**
     * Конструктор десериализатора.
     *
     * @param jweDecrypter объект для расшифровки JWE
     */
    public TokenCookieJweStringDeserializer(JWEDecrypter jweDecrypter) {
        this.jweDecrypter = jweDecrypter;
    }

    /**
     * Десериализует строку в объект Token.
     *
     * @param string зашифрованная строка JWE
     * @return объект Token или null в случае ошибки дешифрования или парсинга
     */
    @Override
    public Token apply(String string) {
        try {
            var encryptedJWT = EncryptedJWT.parse(string);
            encryptedJWT.decrypt(this.jweDecrypter);
            var claimsSet = encryptedJWT.getJWTClaimsSet();
            return new Token(UUID.fromString(claimsSet.getJWTID()), claimsSet.getSubject(),
                    claimsSet.getStringListClaim("authorities"),
                    claimsSet.getIssueTime().toInstant(),
                    claimsSet.getExpirationTime().toInstant());
        } catch (ParseException | JOSEException exception) {
            LOGGER.error(exception.getMessage(), exception);
        }

        return null;
    }
}
