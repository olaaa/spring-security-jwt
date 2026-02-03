package pro.akosarev.sandbox;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.function.Function;

public class RefreshTokenFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/jwt/refresh");


    private Function<Authentication, AccessToken> accessTokenFactory = new DefaultAccessTokenFactory();

    private Function<AccessToken, String> accessTokenStringSerializer = Object::toString;

    private UserDetailsService userDetailsService;

    private ObjectMapper objectMapper = new ObjectMapper();

    public RefreshTokenFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!this.requestMatcher.matches(request)) {
//            если запрос не обрабатывается текущим фильром, то продолжаем выполнение цепочки фильтров безопасности
            filterChain.doFilter(request, response);
        } else {
            Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
            if ((authentication1 instanceof PreAuthenticatedAuthenticationToken) &&
                authentication1.getPrincipal() instanceof TokenUser user) {

                // Стандартный подход: загружаем актуальные данные пользователя из БД
                // Это позволяет учесть изменения в правах пользователя
                var userDetails = userDetailsService.loadUserByUsername(user.getUsername());

                // Создаем новый Authentication с актуальными authorities
                // Создаем новый Authentication с актуальными authorities
                //   по умолчанию                     authentication.setAuthenticated(true);
                var authentication = new PreAuthenticatedAuthenticationToken(
                        userDetails,
                        userDetails.getPassword(),
                        userDetails.getAuthorities()
                );


                // Создаем новый Access Token на основе актуальных данных
                var accessToken = accessTokenFactory.apply(authentication);

                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                this.objectMapper.writeValue(response.getWriter(),
                        new Tokens(this.accessTokenStringSerializer.apply(accessToken),
                                accessToken.expiresAt().toString(), null, null));
                return;
            } else {

//  спринг секьюрити обработает это исключение
                throw new AccessDeniedException("User must be authenticated with JWT");

            }
        }

    }


    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    public void setAccessTokenFactory(Function<Authentication, AccessToken> accessTokenFactory) {
        this.accessTokenFactory = accessTokenFactory;
    }

    public void setAccessTokenStringSerializer(Function<AccessToken, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
}