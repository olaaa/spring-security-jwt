import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import java.util.Collections;
import java.util.List;

public class KeycloakConfigurator {
    public static void main(String[] args) {
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl("http://localhost:8080")
                .realm("master")
                .clientId("admin-cli")
                .username("admin")
                .password("admin")
                .build();

        String realmName = "sandbox-realm";
        
        // Create Realm
        RealmRepresentation realm = new RealmRepresentation();
        realm.setRealm(realmName);
        realm.setEnabled(true);
        try {
            keycloak.realms().create(realm);
            System.out.println("Realm created");
        } catch (Exception e) {
            System.out.println("Realm might already exist: " + e.getMessage());
        }

        // Create Client
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId("server-auth-client");
        client.setPublicClient(true);
        client.setEnabled(true);
        client.setRedirectUris(Collections.singletonList("*"));
        client.setDirectAccessGrantsEnabled(true);

        try {
            keycloak.realm(realmName).clients().create(client);
            System.out.println("Client created");
        } catch (Exception e) {
            System.out.println("Client might already exist: " + e.getMessage());
        }

        // Create Roles
        createRole(keycloak, realmName, "admin");
        createRole(keycloak, realmName, "user");
    }

    private static void createRole(Keycloak keycloak, String realm, String roleName) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(roleName);
        try {
            keycloak.realm(realm).roles().create(role);
            System.out.println("Role " + roleName + " created");
        } catch (Exception e) {
            System.out.println("Role " + roleName + " might already exist");
        }
    }
}
