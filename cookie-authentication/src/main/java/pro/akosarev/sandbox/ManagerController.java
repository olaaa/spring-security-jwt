package pro.akosarev.sandbox;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Контроллер для доступа к разделу менеджера.
 */
@Controller
public class ManagerController {

    /**
     * Возвращает имя шаблона страницы менеджера.
     *
     * @return имя представления "manager"
     */
    @GetMapping("manager")
    public String getManagerPage() {
        return "manager";
    }
}
