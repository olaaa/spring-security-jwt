package pro.akosarev.sandbox;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Контроллер для доступа к разделу менеджера.
 * Использует декларативную авторизацию Spring Security 7.0
 */
@Controller
public class ManagerController {

    /**
     * Возвращает имя шаблона страницы менеджера.
     * Использует @PreAuthorize для проверки ролей (опционально, так как уже настроено в SecurityFilterChain)
     */
    @GetMapping("/manager")
    @PreAuthorize("hasRole('MANAGER')")
    public String getManagerPage() {
        return "manager";
    }
}
