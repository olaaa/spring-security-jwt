package pro.akosarev.sandbox.resource;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/resource")
public class ResourceController {

    @GetMapping("/public")
    public Map<String, String> getPublicData() {
        return Map.of("message", "This is public data for any authenticated user");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('admin')")
    public Map<String, String> getAdminData(Authentication authentication) {
        return Map.of(
                "message", "Hello Admin!",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities().toString()
        );
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('user', 'admin')")
    public Map<String, String> getUserData(Authentication authentication) {
        return Map.of(
                "message", "Hello User!",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities().toString()
        );
    }
}
