package ec.fin.powerbi.app_powerbi.controller;

import ec.fin.powerbi.app_powerbi.dto.LoginRequest;
import ec.fin.powerbi.app_powerbi.persistence.model.Users;
import ec.fin.powerbi.app_powerbi.service.security.ActiveDirectoryAuth2Service;
import ec.fin.powerbi.app_powerbi.service.security.JwtService;
import ec.fin.powerbi.app_powerbi.service.security.dto.AuthResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth1")
@Slf4j
public class Auth2Controller {

    @Autowired
    private ActiveDirectoryAuth2Service authService;

    @Autowired
    private JwtService jwtService;

    /**
     * Endpoint de login con validación completa
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        log.info("Intento de login para usuario: {}", loginRequest.getUsername());

        try {
            // Validar entrada
            if (loginRequest.getUsername() == null || loginRequest.getUsername().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "success", false,
                                "message", "Username es requerido",
                                "timestamp", LocalDateTime.now()
                        ));
            }

            if (loginRequest.getPassword() == null || loginRequest.getPassword().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "success", false,
                                "message", "Password es requerido",
                                "timestamp", LocalDateTime.now()
                        ));
            }

            // Realizar autenticación
            AuthResult authResult = authService.login(
                    loginRequest.getUsername().trim(),
                    loginRequest.getPassword()
            );

            if (authResult.isSuccess()) {
                Users user = authResult.getUser();
                UserDetails userDetails = authResult.getUserDetails();

                // Actualizar último login
                //user.updateLastLogin();

                // Generar tokens JWT
                String accessToken = jwtService.generateToken(userDetails);
                String refreshToken = jwtService.generateRefreshToken(userDetails);

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "Login exitoso");
                response.put("access_token", accessToken);
                response.put("refresh_token", refreshToken);
                response.put("token_type", "Bearer");
                //response.put("expires_in", jwtService.getAccessTokenExpiration());

                // Información del usuario
                Map<String, Object> userInfo = new HashMap<>();
                userInfo.put("username", user.getUsername());
                userInfo.put("Cargo", user.getCargo());
                userInfo.put("deparment", user.getDepartment());
                userInfo.put("email", user.getEmail());
                userInfo.put("fullName", user.getFullName());
                userInfo.put("groups", user.getGroups());
                userInfo.put("authorities", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()));

                response.put("user", userInfo);
                response.put("timestamp", LocalDateTime.now());

                log.info("Login exitoso para usuario: {} ({})", user.getDisplayName(), user.getUsername());
                return ResponseEntity.ok(response);

            } else {
                log.warn("Login fallido para usuario: {} - {}", loginRequest.getUsername(), authResult.getMessage());

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of(
                                "success", false,
                                "message", authResult.getMessage(),
                                "timestamp", LocalDateTime.now()
                        ));
            }

        } catch (Exception e) {
            log.error("Error durante login para usuario: {} - {}", loginRequest.getUsername(), e.getMessage(), e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Error interno del servidor",
                            "timestamp", LocalDateTime.now()
                    ));
        }
    }

    /**
     * Endpoint simplificado de autenticación (solo true/false)
     */
    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody LoginRequest loginRequest) {
        try {
            boolean isAuthenticated = authService.authenticateUser(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
            );

            return ResponseEntity.ok(Map.of(
                    "authenticated", isAuthenticated,
                    "username", loginRequest.getUsername(),
                    "timestamp", LocalDateTime.now()
            ));

        } catch (Exception e) {
            log.error("Error durante autenticación: {}", e.getMessage(), e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "authenticated", false,
                            "error", "Error interno del servidor",
                            "timestamp", LocalDateTime.now()
                    ));
        }
    }

    /**
     * Endpoint para obtener UserDetails de un usuario
     */
    @GetMapping("/userdetails/{username}")
    public ResponseEntity<?> getUserDetails(@PathVariable String username) {

        try {
            log.debug("Obteniendo UserDetails para usuario: {}", username);

            UserDetails userDetails = authService.loadUserByUsername(username);

            Map<String, Object> response = new HashMap<>();
            response.put("username", userDetails.getUsername());
            response.put("enabled", userDetails.isEnabled());
            response.put("accountNonExpired", userDetails.isAccountNonExpired());
            response.put("accountNonLocked", userDetails.isAccountNonLocked());
            response.put("credentialsNonExpired", userDetails.isCredentialsNonExpired());
            response.put("authorities", userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()));
            response.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(response);

        } catch (UsernameNotFoundException e) {
            log.warn("Usuario no encontrado: {}", username);

            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of(
                            "error", "Usuario no encontrado",
                            "username", username,
                            "timestamp", LocalDateTime.now()
                    ));

        } catch (DisabledException e) {

            log.warn("Usuario no encontrado: {}", username);
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of());

        }

    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String refreshToken) {
        return authService.refreshToken(refreshToken);
    }


    @GetMapping("/check-token")
    public ResponseEntity<?> checkToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return authService.checkToken(authHeader);
    }

}