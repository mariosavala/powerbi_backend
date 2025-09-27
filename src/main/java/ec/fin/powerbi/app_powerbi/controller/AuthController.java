package ec.fin.powerbi.app_powerbi.controller;

import ec.fin.powerbi.app_powerbi.dto.ErrorResponse;
import ec.fin.powerbi.app_powerbi.dto.LoginRequest;
import ec.fin.powerbi.app_powerbi.dto.LoginResponse;
import ec.fin.powerbi.app_powerbi.dto.RefreshTokenRequest;
import ec.fin.powerbi.app_powerbi.persistence.model.Users;
import ec.fin.powerbi.app_powerbi.service.security.ActiveDirectoryAuthService;
import ec.fin.powerbi.app_powerbi.service.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final ActiveDirectoryAuthService authService;
    private final JwtService jwtService;

    /**
     * Endpoint para autenticar un usuario contra Active Directory
     * @param loginRequest Credenciales de login
     * @param bindingResult Resultado de validación
     * @param request Solicitud HTTP
     * @return Respuesta con tokens JWT
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest, BindingResult bindingResult, HttpServletRequest request) {
        
        log.info("Intento de login para usuario: {}", loginRequest.getUsername());
        
        // Validar errores de binding
        if (bindingResult.hasErrors()) {
            List<String> errors = bindingResult.getFieldErrors()
                    .stream()
                    .map(FieldError::getDefaultMessage)
                    .collect(Collectors.toList());
            
            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.BAD_REQUEST.value(),
                    "Validation Error",
                    "Errores de validación en la solicitud",
                    request.getRequestURI(),
                    errors
            );
            
            return ResponseEntity.badRequest().body(errorResponse);
        }
        
        try {
            // Autenticar usuario contra Active Directory
            Users user = authService.authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
            
            // Generar tokens JWT
            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            
            // Calcular tiempo de expiración
            long expiresIn = jwtService.getTokenRemainingTime(accessToken);
            
            // Construir información del usuario
            LoginResponse.UserInfo userInfo = LoginResponse.UserInfo.builder()
                    .username(user.getUsername())
                    .displayName(user.getDisplayName())
                    .email(user.getEmail())
                    .department(user.getDepartment())
                    .enabled(user.isEnabled())
                    .roles(user.getAuthorities().stream()
                            .map(auth -> auth.getAuthority())
                            .collect(Collectors.toList()))
                    .groups(user.getGroups())
                    .build();
            
            // Construir respuesta de login
            LoginResponse loginResponse = LoginResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(expiresIn)
                    .userInfo(userInfo)
                    .build();
            
            log.info("Login exitoso para usuario: {}", loginRequest.getUsername());
            return ResponseEntity.ok(loginResponse);
            
        } catch (UsernameNotFoundException e) {

            log.warn("Usuario no encontrado: {}", loginRequest.getUsername());

            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Authentication Failed",
                    "Usuario o contraseña incorrectos",
                    request.getRequestURI()
            );

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            
        } catch (BadCredentialsException e) {

            log.warn("Credenciales inválidas para usuario: {}", loginRequest.getUsername());

            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Authentication Failed",
                    "Usuario o contraseña incorrectos",
                    request.getRequestURI()
            );

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            
        } catch (DisabledException e) {

            log.warn("Cuenta deshabilitada para usuario: {}", loginRequest.getUsername());

            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.FORBIDDEN.value(),
                    "Account Disabled",
                    "La cuenta del usuario está deshabilitada",
                    request.getRequestURI()
            );

            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
            
        } catch (Exception e) {

            log.error("Error durante el login para usuario {}: {}", loginRequest.getUsername(), e.getMessage(), e);

            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Internal Server Error",
                    "Error interno del servidor durante la autenticación",
                    request.getRequestURI()
            );

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);

        }
    }

    /**
     * Endpoint para refrescar un token JWT
     * @param refreshRequest Solicitud con refresh token
     * @param bindingResult Resultado de validación
     * @param request Solicitud HTTP
     * @return Nuevos tokens JWT
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshRequest, BindingResult bindingResult, HttpServletRequest request) {
        
        log.debug("Solicitud de refresh token");
        
        // Validar errores de binding
        if (bindingResult.hasErrors()) {

            List<String> errors = bindingResult.getFieldErrors()
                    .stream()
                    .map(FieldError::getDefaultMessage)
                    .collect(Collectors.toList());
            
            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.BAD_REQUEST.value(),
                    "Validation Error",
                    "Errores de validación en la solicitud",
                    request.getRequestURI(),
                    errors
            );
            
            return ResponseEntity.badRequest().body(errorResponse);
        }
        
        try {

            String refreshToken = refreshRequest.getRefreshToken();
            

            
            // Extraer username del refresh token
            String username = jwtService.extractUserName(refreshToken);
            
            // Cargar usuario desde AD
            Users user = (Users) authService.loadUserByUsername(username);
            
            // Verificar que el usuario sigue activo
            if (!user.isEnabled()) {
                ErrorResponse errorResponse = ErrorResponse.of(
                        HttpStatus.FORBIDDEN.value(),
                        "Account Disabled",
                        "La cuenta del usuario está deshabilitada",
                        request.getRequestURI()
                );
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
            }
            
            // Generar nuevos tokens
            String newAccessToken = jwtService.generateToken(user);
            String newRefreshToken = jwtService.generateRefreshToken(user);
            
            // Calcular tiempo de expiración
            long expiresIn = jwtService.getTokenRemainingTime(newAccessToken);
            
            // Construir información del usuario actualizada
            LoginResponse.UserInfo userInfo = LoginResponse.UserInfo.builder()
                    .username(user.getUsername())
                    .displayName(user.getDisplayName())
                    .email(user.getEmail())
                    .department(user.getDepartment())
                    .enabled(user.isEnabled())
                    .roles(user.getAuthorities().stream()
                            .map(auth -> auth.getAuthority())
                            .collect(Collectors.toList()))
                    .groups(user.getGroups())
                    .build();
            
            // Construir respuesta
            LoginResponse loginResponse = LoginResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .tokenType("Bearer")
                    .expiresIn(expiresIn)
                    .userInfo(userInfo)
                    .build();
            
            log.info("Refresh token exitoso para usuario: {}", username);
            return ResponseEntity.ok(loginResponse);
            
        } catch (UsernameNotFoundException e) {
            log.warn("Usuario no encontrado durante refresh token");
            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.UNAUTHORIZED.value(),
                    "User Not Found",
                    "Usuario no encontrado",
                    request.getRequestURI()
            );
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            
        } catch (Exception e) {
            log.error("Error durante refresh token: {}", e.getMessage(), e);
            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Internal Server Error",
                    "Error interno del servidor durante la renovación del token",
                    request.getRequestURI()
            );
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para logout (invalidar tokens del lado del cliente)
     * @param request Solicitud HTTP
     * @return Respuesta de confirmación
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        log.info("Solicitud de logout");
        
        // En una implementación JWT stateless, el logout se maneja en el cliente
        // eliminando los tokens. Aquí solo confirmamos la operación.
        
        return ResponseEntity.ok().body(
                java.util.Map.of(
                        "message", "Logout exitoso",
                        "timestamp", java.time.LocalDateTime.now()
                )
        );
    }

    /**
     * Endpoint para validar un token
     * @param request Solicitud HTTP con Authorization header
     * @return Estado del token
     */
    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(HttpServletRequest request) {

        String authHeader = request.getHeader("Authorization");
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Missing Token",
                    "Token de autorización requerido",
                    request.getRequestURI()
            );
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
        
        String token = authHeader.substring(7);
        
        try {

            
            // Extraer username y validar token
            String username = jwtService.extractUserName(token);
            Users user = (Users) authService.loadUserByUsername(username);

            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Invalid Token",
                    "Token inválido o expirado",
                    request.getRequestURI()
            );
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            
        } catch (Exception e) {
            log.debug("Error validando token: {}", e.getMessage());
            ErrorResponse errorResponse = ErrorResponse.of(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Token Validation Failed",
                    "Validación de token fallida",
                    request.getRequestURI()
            );
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }
}
