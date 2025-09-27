package ec.fin.powerbi.app_powerbi.service.security.dto;

import ec.fin.powerbi.app_powerbi.persistence.model.Users;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.userdetails.UserDetails;

@Getter
@Setter
public class AuthResult {

    private boolean success;
    private String message;
    private Users user;
    private UserDetails userDetails;

    private AuthResult(boolean success, String message, Users user, UserDetails userDetails) {
        this.success = success;
        this.message = message;
        this.user = user;
        this.userDetails = userDetails;
    }

    public static AuthResult success(Users user, UserDetails userDetails) {
        return new AuthResult(true, "Autenticación exitosa", user, userDetails);
    }

    public static AuthResult failure(String message) {
        return new AuthResult(false, message, null, null);
    }


}
