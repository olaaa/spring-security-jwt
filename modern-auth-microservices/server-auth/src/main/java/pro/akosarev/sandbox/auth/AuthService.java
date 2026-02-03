package pro.akosarev.sandbox.auth;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.Map;

@Service
public class AuthService {

    private final Keycloak keycloak;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.token-uri}")
    private String tokenUrl;

    public AuthService(Keycloak keycloak) {
        this.keycloak = keycloak;
    }

    public String register(RegistrationRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());

        CredentialRepresentation password = new CredentialRepresentation();
        password.setTemporary(false);
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue(request.password());
        user.setCredentials(Collections.singletonList(password));

        Response response = keycloak.realm(realm).users().create(user);
        if (response.getStatus() != 201) {
            throw new RuntimeException("Failed to create user: " + response.getStatus());
        }

        // Get user ID
        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

        // Assign 'user' role
        var rolesResource = keycloak.realm(realm).roles();
        var userResource = keycloak.realm(realm).users().get(userId);
        
        try {
            var roleRepresentation = rolesResource.get("user").toRepresentation();
            userResource.roles().realmLevel().add(Collections.singletonList(roleRepresentation));
        } catch (Exception e) {
            System.err.println("Failed to assign role: " + e.getMessage());
        }

        return "User created successfully";
    }

    public Map<String, Object> login(LoginRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("client_id", clientId);
        map.add("username", request.username());
        map.add("password", request.password());

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, entity, Map.class);
        return response.getBody();
    }
}

record RegistrationRequest(String username, String email, String password, String firstName, String lastName) {}
record LoginRequest(String username, String password) {}
