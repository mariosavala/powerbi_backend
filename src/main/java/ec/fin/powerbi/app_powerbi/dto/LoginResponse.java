package ec.fin.powerbi.app_powerbi.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponse {
    
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private long expiresIn; // en segundos
    private UserInfo userInfo;
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class UserInfo {
        private String username;
        private String displayName;
        private String email;
        private String department;
        private String cargo;
        private String Oficina;
        private boolean enabled;
        private List<String> roles;
        private List<String> groups;
    }
}
