package ec.fin.powerbi.app_powerbi.persistence.model;

import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Users implements UserDetails {

    @NotBlank(message = "El campo username es obligatorio")
    private String username;
    private String firstName;
    private String lastName;
    private String displayName;
    private String userPrincipalName;
    private String email;
    private String department;
    private String cargo;
    private LocalDateTime lastLogin;
    private boolean accountEnabled = true;
    private boolean accountLocked = false;
    private boolean passwordExpired = false;
    private boolean passwordNeverExpires = false;
    private Integer userAccountControl;
    private List<String> groups;
    private String distinguishedName;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (groups == null || groups.isEmpty()) {
            return List.of(new SimpleGrantedAuthority("ROLE_USER"));
        }
        return groups.stream()
                .map(group -> new SimpleGrantedAuthority("ROLE_" + group.toUpperCase()))
                .collect(Collectors.toList());
    }

    /**
     * Verifica si el usuario puede iniciar sesión
     */
    public boolean canLogin() {
        return accountEnabled && !accountLocked && !passwordExpired;
    }

    /**
     * Obtiene el nombre completo del usuario
     */
    public String getFullName() {

        StringBuilder fullName = new StringBuilder();

        if (firstName != null && !firstName.trim().isEmpty()) {
            fullName.append(firstName.trim());
        }

        if (lastName != null && !lastName.trim().isEmpty()) {

            if (fullName.length() > 0) {
                fullName.append(" ");
            }
            fullName.append(lastName.trim());
        }

        return fullName.length() > 0 ? fullName.toString() : displayName;
    }

    /**
     * Obtiene una descripción del estado de la cuenta
     */
    public String getAccountStatusDescription() {

        if (!accountEnabled) {
            return "Cuenta deshabilitada";
        } else if (accountLocked) {
            return "Cuenta bloqueada";
        } else if (passwordExpired) {
            return "Contraseña expirada";
        } else {
            return "Cuenta activa";
        }
    }

    @Override
    public String getPassword() {
        // Los usuarios de AD no tienen password almacenado localmente
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    
    @Override
    public boolean isEnabled() {
        return accountEnabled;
    }
}
