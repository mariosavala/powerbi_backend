package ec.fin.powerbi.app_powerbi.service.security;

import ec.fin.powerbi.app_powerbi.persistence.model.Users;
import ec.fin.powerbi.app_powerbi.service.security.dto.AuthResult;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.PartialResultException;
import org.springframework.ldap.ReferralException;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class ActiveDirectoryAuth2Service implements UserDetailsService {

    @Autowired
    private LdapTemplate ldapTemplate;

    @Autowired
    private JwtService jwtService;

    @Value("${ad.user-search-base}")
    private String userSearchBase;

    @Value("${ad.user-search-filter}")
    private String userSearchFilter;

    @Value("${spring.ldap.urls}")
    private String ldapUrl;

    @Value("${spring.ldap.username}")
    private String ldapUsername;

    @Value("${spring.ldap.password}")
    private String ldapPassword;

    /**
     * Implementación de UserDetailsService para Spring Security
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.debug("loadUserByUsername - buscando usuario: {}", username);

        Users user = findUserInAD(username);

        if (user == null) {
            log.warn("Usuario {} no encontrado en AD", username);
            throw new UsernameNotFoundException("Usuario no encontrado: " + username);
        }

        if (!user.isAccountEnabled()) {
            log.warn("Usuario {} está deshabilitado en AD", username);
            throw new DisabledException("La cuenta está deshabilitada");
        }

        // Construir UserDetails de Spring Security
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password("N/A") // No se necesita, ya se validó vía LDAP
                .authorities(getAuthoritiesForUser(user))
                .accountExpired(false)
                .accountLocked(user.isAccountLocked())
                .credentialsExpired(user.isPasswordExpired())
                .disabled(!user.isAccountEnabled())
                .build();
    }

    /**
     * Método de login con validación de contraseña contra Active Directory
     */
    public AuthResult login(String username, String password) {

        log.debug("Iniciando proceso de login para usuario: {}", username);

        // Validar parámetros
        if (username == null || username.trim().isEmpty()) {
            log.warn("Username vacío o nulo");
            return AuthResult.failure("Username es requerido");
        }

        if (password == null || password.trim().isEmpty()) {
            log.warn("Password vacío o nulo para usuario: {}", username);
            return AuthResult.failure("Password es requerido");
        }

        try {
            // 1. Buscar el usuario en AD
            Users user = findUserInAD(username);
            if (user == null) {
                log.warn("Usuario no encontrado en AD: {}", username);
                return AuthResult.failure("Usuario no encontrado");
            }

            // 2. Verificar estado de la cuenta
            if (!user.isAccountEnabled()) {
                log.warn("Cuenta deshabilitada para usuario: {}", username);
                return AuthResult.failure("La cuenta está deshabilitada");
            }

            if (user.isAccountLocked()) {
                log.warn("Cuenta bloqueada para usuario: {}", username);
                return AuthResult.failure("La cuenta está bloqueada");
            }

            if (user.isPasswordExpired()) {
                log.warn("Contraseña expirada para usuario: {}", username);
                return AuthResult.failure("La contraseña ha expirado");
            }

            // 3. Validar contraseña contra Active Directory
            boolean isValidPassword = validatePasswordAgainstAD(user.getDistinguishedName(), password);

            if (!isValidPassword) {
                log.warn("Credenciales inválidas para usuario: {}", username);
                return AuthResult.failure("Credenciales inválidas");
            }

            // 4. Login exitoso
            log.info("Login exitoso para usuario: {} ({})", user.getDisplayName(), user.getUsername());

            // Crear UserDetails para el resultado
            UserDetails userDetails = org.springframework.security.core.userdetails.User
                    .withUsername(user.getUsername())
                    .password("N/A")
                    .authorities(getAuthoritiesForUser(user))
                    .accountExpired(false)
                    .accountLocked(false)
                    .credentialsExpired(false)
                    .disabled(false)
                    .build();

            return AuthResult.success(user, userDetails);

        } catch (Exception e) {
            log.error("Error durante el proceso de login para usuario: {} - {}", username, e.getMessage(), e);
            return AuthResult.failure("Error interno durante la autenticación");
        }
    }

    /**
     * Método simplificado de login que solo retorna boolean
     */
    public boolean authenticateUser(String username, String password) {
        AuthResult result = login(username, password);
        return result.isSuccess();
    }

    /**
     * Validar contraseña contra Active Directory usando bind
     */
    private boolean validatePasswordAgainstAD(String userDN, String password) {
        try {
            log.debug("Validando contraseña para DN: {}", userDN);

            // Configurar entorno para bind authentication
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, userDN);
            env.put(Context.SECURITY_CREDENTIALS, password);
            env.put("java.naming.referral", "follow");
            env.put("com.sun.jndi.ldap.connect.timeout", "5000");
            env.put("com.sun.jndi.ldap.read.timeout", "10000");

            // Intentar bind con las credenciales del usuario
            InitialDirContext userContext = new InitialDirContext(env);

            // Si llegamos aquí, el bind fue exitoso
            log.debug("Validación de contraseña exitosa para DN: {}", userDN);
            userContext.close();
            return true;

        } catch (AuthenticationException e) {
            log.debug("Credenciales inválidas para DN: {} - {}", userDN, e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Error validando contraseña para DN: {} - {}", userDN, e.getMessage());
            return false;
        }
    }

    /**
     * Buscar usuario en Active Directory (método existente mejorado)
     */
    public Users findUserInAD(String username) {

        log.debug("Buscando usuario en AD: {}", username);

        String sAMAccountName = extractSAMAccountName(username);
        String originalUsername = username;

        log.debug("Username original: '{}'", originalUsername);
        log.debug("sAMAccountName extraído: '{}'", sAMAccountName);

        try {
            String searchBase = "";
            String[] searchFilters = {
                    "(&(objectClass=user)(sAMAccountName=" + sAMAccountName + "))",
                    "(&(objectClass=user)(userPrincipalName=" + originalUsername + "))",
                    "(&(objectClass=user)(mail=" + originalUsername + "))",
                    "(&(objectClass=user)(|(sAMAccountName=" + sAMAccountName + ")(userPrincipalName=" + originalUsername + ")(mail=" + originalUsername + ")))"
            };

            for (String filter : searchFilters) {
                try {
                    log.debug("Probando filtro: '{}'", filter);

                    SearchControls searchControls = new SearchControls();
                    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                    searchControls.setCountLimit(10);
                    searchControls.setTimeLimit(15000);

                    searchControls.setReturningAttributes(new String[]{
                            "sAMAccountName", "userPrincipalName", "mail", "displayName",
                            "givenName", "sn", "distinguishedName", "userAccountControl",
                            "objectClass", "memberOf", "accountExpires", "pwdLastSet","description","physicalDeliveryOfficeName"
                    });

                    List<Users> users = ldapTemplate.search(
                            searchBase,
                            filter,
                            searchControls,
                            new EnhancedUserAttributesMapper()
                    );

                    if (!users.isEmpty()) {
                        Users user = users.get(0);
                        log.info("Usuario encontrado con filtro '{}': {} ({})",
                                filter, user.getDisplayName(), user.getUsername());

                        user.setGroups(getUserGroups(user.getDistinguishedName()));
                        return user;
                    }

                } catch (PartialResultException | ReferralException e) {
                    log.debug("Excepción de referencia (continuando): {}", e.getMessage());
                    continue;
                } catch (Exception e) {
                    log.debug("Error con filtro '{}': {}", filter, e.getMessage());
                }
            }

            log.warn("Usuario no encontrado en AD: {}", username);
            return null;

        } catch (Exception e) {
            log.error("Error general buscando usuario en AD: {} - {}", username, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Extracción de sAMAccountName
     */
    private String extractSAMAccountName(String username) {
        if (username == null || username.trim().isEmpty()) {
            return username;
        }

        String trimmed = username.trim();

        if (trimmed.contains("@")) {
            return trimmed.substring(0, trimmed.indexOf("@"));
        }

        if (trimmed.contains("\\")) {
            return trimmed.substring(trimmed.indexOf("\\") + 1);
        }

        return trimmed;
    }

    /**
     * Obtener grupos del usuario
     */
    private List<String> getUserGroups(String userDN) {

        if (userDN == null || userDN.trim().isEmpty()) {
            return Collections.singletonList("Users");
        }

        try {
            String groupFilter = "(member=" + userDN + ")";
            log.debug("Buscando grupos con filtro: {}", groupFilter);

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setCountLimit(100);
            searchControls.setTimeLimit(10000);
            searchControls.setReturningAttributes(new String[]{"cn", "distinguishedName"});

            List<String> groups = ldapTemplate.search(
                    "",
                    groupFilter,
                    searchControls,
                    new AttributesMapper<String>() {
                        @Override
                        public String mapFromAttributes(Attributes attributes) throws NamingException, javax.naming.NamingException {
                            Attribute cnAttribute = attributes.get("cn");
                            return cnAttribute != null ? cnAttribute.get().toString() : null;
                        }
                    }
            );

            groups = groups.stream()
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            log.debug("Grupos encontrados para {}: {}", userDN, groups);

            return groups.isEmpty() ? Collections.singletonList("Users") : groups;

        } catch (Exception e) {
            log.error("Error obteniendo grupos para {}: {}", userDN, e.getMessage());
            return Collections.singletonList("Users");
        }
    }

    /**
     * Convierte los grupos de AD a GrantedAuthorities
     */
    private Collection<? extends GrantedAuthority> getAuthoritiesForUser(Users user) {
        if (user.getGroups() == null || user.getGroups().isEmpty()) {
            return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return user.getGroups().stream()
                .map(group -> new SimpleGrantedAuthority("ROLE_" + group.toUpperCase().replace(" ", "_")))
                .collect(Collectors.toList());
    }

    /**
     * UserAttributesMapper mejorado con información de cuenta
     */
    public static class EnhancedUserAttributesMapper implements AttributesMapper<Users> {

        @Override
        public Users mapFromAttributes(Attributes attributes) throws NamingException {
            Users user = new Users();

            try {
                user.setUsername(getAttributeValue(attributes, "sAMAccountName"));
                user.setDisplayName(getAttributeValue(attributes, "displayName"));
                user.setEmail(getAttributeValue(attributes, "mail"));
                user.setFirstName(getAttributeValue(attributes, "givenName"));
                user.setLastName(getAttributeValue(attributes, "sn"));
                user.setDistinguishedName(getAttributeValue(attributes, "distinguishedName"));
                user.setDepartment(getAttributeValue(attributes, "physicalDeliveryOfficeName"));
                user.setCargo(getAttributeValue(attributes, "description"));

                String upn = getAttributeValue(attributes, "userPrincipalName");
                if (upn != null) {
                    user.setUserPrincipalName(upn);
                }

                // Procesar userAccountControl
                String userAccountControl = getAttributeValue(attributes, "userAccountControl");
                if (userAccountControl != null) {
                    try {
                        int uac = Integer.parseInt(userAccountControl);
                        user.setAccountEnabled((uac & 2) == 0);
                        user.setAccountLocked((uac & 0x0010) != 0);
                        user.setPasswordExpired((uac & 0x800000) != 0);
                        user.setPasswordNeverExpires((uac & 0x10000) != 0);
                    } catch (NumberFormatException e) {
                        user.setAccountEnabled(true);
                        user.setAccountLocked(false);
                        user.setPasswordExpired(false);
                    }
                } else {
                    user.setAccountEnabled(true);
                    user.setAccountLocked(false);
                    user.setPasswordExpired(false);
                }

                log.debug("Usuario mapeado: {} ({}) - Habilitado: {}",
                        user.getDisplayName(), user.getUsername(), user.isAccountEnabled());

            } catch (Exception e) {
                log.error("Error mapeando usuario: {}", e.getMessage(), e);
            }

            return user;
        }

        private static String getAttributeValue(Attributes attributes, String attributeName) {
            try {
                Attribute attribute = attributes.get(attributeName);
                return attribute != null ? attribute.get().toString() : null;
            } catch (Exception e) {
                return null;
            }
        }
    }

    public ResponseEntity<?> refreshToken(String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token inválido: "); // O una respuesta JSON indicando el error
        }

        // EXTRAIGO LA PALABRA "Bearer"
        String refreshToken = authHeader.substring(7);

        if(refreshToken.isEmpty()){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("refreshToken no proporcionado: ");
        }

        try {

            Claims claims= Jwts.parserBuilder()
                    .setSigningKey(jwtService.getSignInKey())
                    .build()
                    .parseClaimsJws(refreshToken)
                    .getBody();

            String username=claims.getSubject();

            String typeRefreshToken = (String) claims.get("token_type");

            if(!"refreshToken".equals(typeRefreshToken)){
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("El token no es de tipo refresh.");
            }

            Users user = findUserInAD(username);

            // Crear UserDetails para el resultado
            UserDetails authUser = org.springframework.security.core.userdetails.User
                    .withUsername(user.getUsername())
                    .password("N/A")
                    .authorities(getAuthoritiesForUser(user))
                    .accountExpired(false)
                    .accountLocked(false)
                    .credentialsExpired(false)
                    .disabled(false)
                    .build();


            String newAccessToken = jwtService.generateToken(authUser);
            String newRefreshToken=jwtService.generateRefreshToken(authUser);

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Tokens actualizados correctamente");
            response.put("data", Map.of(
                    "token", newAccessToken,
                    "refreshToken", newRefreshToken
            ));

            return ResponseEntity.ok(response);

        } catch (Exception e) {

            Map<String, Object> responseError = new HashMap<>();
            responseError.put("status", "error");
            responseError.put("message", "refreshToken inválido: "+e.getMessage());

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseError);
        }

    }

    public ResponseEntity<?> checkToken(String authHeader){

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token inválido: "); // O una respuesta JSON indicando el error
        }
        // EXTRAIGO LA PALABRA "Bearer"
        String token = authHeader.substring(7);

        try {

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(jwtService.getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();

            // Extraer authorities en lugar de roles
            List<Map<String, String>> rawAuthorities = (List<Map<String, String>>) claims.get("authorities");
            List<String> roles = rawAuthorities.stream()
                    .map(auth -> auth.get("authority"))
                    .toList();

            long expiresIn = claims.getExpiration().getTime() / 1000 - System.currentTimeMillis() / 1000;

            Map<String, Object> resp = new HashMap<>();
            resp.put("status", "success");
            resp.put("message", "Token válido");
            resp.put("data", Map.of(
                    "username", username,
                    "roles", roles,
                    "tokenType", "Bearer",
                    "expiresIn", expiresIn,
                    "token", token
            ));

            return ResponseEntity.ok(resp);


        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token inválido");
        }


    }

}

