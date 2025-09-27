package ec.fin.powerbi.app_powerbi.service.security;

import ec.fin.powerbi.app_powerbi.persistence.model.Users;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.PartialResultException;
import org.springframework.ldap.ReferralException;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.odm.annotations.Attribute;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
public class ActiveDirectoryAuthService implements UserDetailsService {

    private final JwtService  jwtService;

    private final LdapTemplate ldapTemplate;
    
    @Value("${ad.domain}")
    private String domain;
    
    @Value("${ad.url}")
    private String adUrl;
    
    @Value("${ad.search-base}")
    private String searchBase;
    
    @Value("${ad.user-search-base}")
    private String userSearchBase;
    
    @Value("${ad.user-search-filter}")
    private String userSearchFilter;
    
    @Value("${ad.group-search-base}")
    private String groupSearchBase;

    public ActiveDirectoryAuthService(JwtService jwtService, LdapTemplate ldapTemplate) {
        this.jwtService = jwtService;
        this.ldapTemplate = ldapTemplate;
    }

    /**
     * Autentica un usuario contra Active Directory
     * @param username Nombre de usuario
     * @param password Contraseña
     * @return Usuario autenticado
     * @throws BadCredentialsException Si las credenciales son inválidas
     * @throws DisabledException Si la cuenta está deshabilitada
     */
    public Users authenticateUser(String username, String password) {

        log.debug("Intentando autenticar usuario: {}", username);
        
        try {
            // ENFOQUE DIRECTO: Autenticar directamente sin búsqueda previa
            String[] userFormats = {
                username + "@coopsanjose.local",
                username,
                "COOPSANJOSE\\" + username.replace("@coopsanjose.local", "")
            };
            
            for (String userFormat : userFormats) {
                log.debug("Probando autenticación directa con formato: {}", userFormat);
                
                if (performDirectLdapAuthentication(userFormat, password)) {
                    log.info("Autenticación directa exitosa para: {} con formato: {}", username, userFormat);

                    // Crear usuario básico sin búsqueda en AD
                    Users user = Users.builder()
                            .username(username.replace("@coopsanjose.local", ""))
                            .displayName(username)
                            .email(username.contains("@") ? username : username + "@coopsanjose.fin.ec")
                            .accountEnabled(true)
                            .groups(java.util.Arrays.asList("Users"))
                            .build();
                    
                    return user;
                }
            }
            
            log.warn("Credenciales inválidas para usuario: {}", username);
            throw new BadCredentialsException("Credenciales inválidas");
            
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error durante la autenticación del usuario {}: {}", username, e.getMessage());
            throw new BadCredentialsException("Error de autenticación: " + e.getMessage());
        }
    }


    /**
     * Realiza la autenticación LDAP directa
     * @param username Nombre de usuario en diferentes formatos
     * @param password Contraseña
     * @return true si la autenticación es exitosa
     */
    private boolean performDirectLdapAuthentication(String username, String password) {

        log.debug("Realizando autenticación LDAP directa para: {}", username);

        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(adUrl);
        contextSource.setUserDn(username);
        contextSource.setPassword(password);

        DirContext context = null;
        try {
            contextSource.afterPropertiesSet();
            context = contextSource.getContext(username, password);
            log.debug("Autenticación LDAP directa exitosa para: {}", username);
            return true;
        } catch (Exception e) {
            log.debug("Autenticación LDAP directa fallida para {}: {}", username, e.getMessage());
            return false;
        } finally {
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException e) {
                    log.warn("Error cerrando contexto LDAP: {}", e.getMessage());
                }
            }
        }
    }

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
                .authorities(getAuthoritiesForUser(user)) // Aquí conviertes grupos en roles
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(!user.isAccountEnabled())
                .build();
    }

    /**
     * Convierte los grupos de AD a GrantedAuthorities
     */
    private Collection<? extends GrantedAuthority> getAuthoritiesForUser(Users user) {
        if (user.getGroups() == null || user.getGroups().isEmpty()) {
            return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return user.getGroups().stream()
                .map(group -> new SimpleGrantedAuthority("ROLE_" + group.toUpperCase()))
                .collect(Collectors.toList());
    }


    private Users findUserInAD(String username) {
        log.debug("🔍 Iniciando búsqueda de usuario en AD: {}", username);

        // PASO 1: EXTRAER CORRECTAMENTE EL sAMAccountName
        String sAMAccountName = extractSAMAccountName(username);
        String originalUsername = username;

        log.info("📧 Username original: '{}'", originalUsername);
        log.info("👤 sAMAccountName extraído: '{}'", sAMAccountName);

        // VERIFICAR QUE LA EXTRACCIÓN FUNCIONÓ
        if (sAMAccountName.equals(originalUsername) && originalUsername.contains("@")) {
            log.warn("⚠️ La extracción del sAMAccountName no funcionó correctamente!");
            // Forzar la extracción manualmente
            sAMAccountName = originalUsername.substring(0, originalUsername.indexOf("@"));
            log.info("🔧 sAMAccountName corregido manualmente: '{}'", sAMAccountName);
        }

        try {
            // PASO 2: Crear un filtro súper simple primero
            String simpleFilter = "(sAMAccountName=" + sAMAccountName + ")";
            log.debug("🧪 Probando filtro simple primero: {}", simpleFilter);

            try {
                SearchControls simpleControls = new SearchControls();
                simpleControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                simpleControls.setCountLimit(5);
                simpleControls.setTimeLimit(10000);

                List<Users> simpleResult = ldapTemplate.search(
                        "DC=coopsanjose,DC=local",
                        simpleFilter,
                        simpleControls,
                        new UserAttributesMapper()
                );

                if (!simpleResult.isEmpty()) {
                    Users user = simpleResult.get(0);
                    log.info("✅ Usuario encontrado con filtro simple: {}", user.getDisplayName());
                    //user.setGroups(getUserGroups(user.getDistinguishedName()));

                    return user;
                }

            } catch (Exception e) {
                log.debug("❌ Filtro simple falló: {}", e.getMessage());
            }

            // PASO 3: Probar diferentes combinaciones de filtros CORRECTOS
            String[] searchBases = {
                    "DC=coopsanjose,DC=local"
            };

            // FILTROS CORREGIDOS - NO usar el email completo en sAMAccountName
            String[] searchFilters = {
                    // CORRECTO: sAMAccountName sin dominio
                    "(&(objectClass=user)(sAMAccountName=" + sAMAccountName + "))",
                    // CORRECTO: userPrincipalName con dominio
                    "(&(objectClass=user)(userPrincipalName=" + originalUsername + "))",
                    // CORRECTO: mail con dominio
                    "(&(objectClass=user)(mail=" + originalUsername + "))",
                    // Filtro combinado CORRECTO
                    "(&(objectClass=user)(|(sAMAccountName=" + sAMAccountName + ")(userPrincipalName=" + originalUsername + ")(mail=" + originalUsername + ")))",
                    // Probar con person también
                    "(&(objectClass=person)(sAMAccountName=" + sAMAccountName + "))"
            };

            for (String searchBase : searchBases) {
                for (String filter : searchFilters) {
                    try {
                        log.debug("📍 Probando - Base: '{}', Filtro: '{}'", searchBase, filter);

                        SearchControls searchControls = new SearchControls();
                        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                        searchControls.setCountLimit(10);
                        searchControls.setTimeLimit(15000);

                        // Atributos específicos para optimizar la búsqueda
                        searchControls.setReturningAttributes(new String[]{
                                "sAMAccountName", "userPrincipalName", "mail", "displayName",
                                "givenName", "sn", "distinguishedName", "userAccountControl",
                                "objectClass"
                        });

                        List<Users> users = ldapTemplate.search(
                                searchBase,
                                filter,
                                searchControls,
                                new UserAttributesMapper()
                        );

                        if (!users.isEmpty()) {
                            Users user = users.get(0);
                            log.info("✅ Usuario encontrado - Base: '{}', Filtro: '{}', Usuario: {} ({})",
                                    searchBase, filter, user.getDisplayName(), user.getUsername());

                            //user.setGroups(getUserGroups(user.getDistinguishedName()));
                            return user;
                        } else {
                            log.debug("🔍 No se encontraron resultados con este filtro");
                        }

                    } catch (PartialResultException e) {
                        log.debug("⚠️ PartialResultException (continuando): {}", e.getMessage());
                        continue;
                    } catch (ReferralException e) {
                        log.debug("⚠️ ReferralException (continuando): {}", e.getMessage());
                        continue;
                    } catch (Exception e) {
                        log.debug("❌ Error con base '{}' y filtro '{}': {}",
                                searchBase, filter, e.getMessage());
                    }
                }
            }

            // PASO 4: Diagnóstico adicional
            performDetailedDiagnostic(sAMAccountName, originalUsername);

            log.warn("❌ Usuario no encontrado en AD: {}", username);
            return null;

        } catch (Exception e) {
            log.error("❌ Error general buscando usuario en AD: {} - {}", username, e.getMessage(), e);
            return null;
        }
    }

    /**
     * MÉTODO CORREGIDO para extraer sAMAccountName
     */
    private String extractSAMAccountName(String username) {
        if (username == null || username.trim().isEmpty()) {
            return username;
        }

        String trimmed = username.trim();
        log.debug("🔧 Extrayendo sAMAccountName de: '{}'", trimmed);

        // Si contiene @, extraer la parte antes del @
        if (trimmed.contains("@")) {
            String extracted = trimmed.substring(0, trimmed.indexOf("@"));
            log.debug("✂️ Extraído de formato email: '{}' -> '{}'", trimmed, extracted);
            return extracted;
        }

        // Si contiene \, extraer la parte después del \
        if (trimmed.contains("\\")) {
            String extracted = trimmed.substring(trimmed.indexOf("\\") + 1);
            log.debug("✂️ Extraído de formato DOMAIN\\user: '{}' -> '{}'", trimmed, extracted);
            return extracted;
        }

        log.debug("➡️ Username sin formato especial, devolviendo tal como está: '{}'", trimmed);
        return trimmed;
    }

    /**
     * Diagnóstico detallado cuando no se encuentra el usuario
     */
    private void performDetailedDiagnostic(String sAMAccountName, String originalUsername) {
        log.info("🔍 Iniciando diagnóstico detallado...");

        try {
            // Buscar usuarios similares
            log.debug("🔍 Buscando usuarios con sAMAccountName similar a '{}'...", sAMAccountName);

            String wildcardFilter = "(sAMAccountName=" + sAMAccountName.substring(0, Math.min(3, sAMAccountName.length())) + "*)";

            SearchControls diagnosticControls = new SearchControls();
            diagnosticControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            diagnosticControls.setCountLimit(10);
            diagnosticControls.setTimeLimit(5000);
            diagnosticControls.setReturningAttributes(new String[]{"sAMAccountName", "userPrincipalName", "displayName"});

            List<String> similarUsers = ldapTemplate.search(
                    "DC=coopsanjose,DC=local",
                    wildcardFilter,
                    diagnosticControls,
                    new AttributesMapper<String>() {
                        @Override
                        public String mapFromAttributes(Attributes attributes) throws NamingException {
                            String sam = getAttributeValue(attributes, "sAMAccountName");
                            String upn = getAttributeValue(attributes, "userPrincipalName");
                            String display = getAttributeValue(attributes, "displayName");
                            return String.format("sAM:'%s', UPN:'%s', Display:'%s'", sam, upn, display);
                        }

                        private String getAttributeValue(Attributes attributes, String attributeName) {
                            try {
                                Attribute attribute = (Attribute) attributes.get(attributeName);
                                return attribute != null ? ((javax.naming.directory.Attribute) attribute).get().toString() : "null";
                            } catch (Exception e) {
                                return "error";
                            }
                        }
                    }
            );

            if (!similarUsers.isEmpty()) {
                log.info("👥 Usuarios similares encontrados:");
                similarUsers.forEach(user -> log.info("   - {}", user));
            } else {
                log.info("❌ No se encontraron usuarios similares");
            }

            // Verificar conectividad básica
            log.debug("🔍 Verificando conectividad básica...");
            List<String> rootObjects = ldapTemplate.search(
                    "",
                    "(objectClass=*)",
                    SearchControls.ONELEVEL_SCOPE,
                    new AttributesMapper<String>() {
                        @Override
                        public String mapFromAttributes(Attributes attributes) throws NamingException {
                            return attributes.get("distinguishedName").get().toString();
                        }
                    }
            );

            log.info("📁 Objetos en la raíz: {}", rootObjects.size());
            rootObjects.forEach(obj -> log.debug("   - {}", obj));

        } catch (Exception e) {
            log.error("❌ Error en diagnóstico: {}", e.getMessage());
        }
    }


    /**
     * Mapper para mapear atributos de AD a objeto Users
     */
    private static class UserAttributesMapper implements AttributesMapper<Users> {
        
        @Override
        public Users mapFromAttributes(Attributes attrs) throws NamingException {
            Users.UsersBuilder userBuilder = Users.builder();
            
            // Mapear atributos básicos
            if (attrs.get("sAMAccountName") != null) {
                userBuilder.username((String) attrs.get("sAMAccountName").get());
            }
            
            if (attrs.get("displayName") != null) {
                userBuilder.displayName((String) attrs.get("displayName").get());
            }
            
            if (attrs.get("mail") != null) {
                userBuilder.email((String) attrs.get("mail").get());
            }
            
            if (attrs.get("department") != null) {
                userBuilder.department((String) attrs.get("department").get());
            }
            
            if (attrs.get("distinguishedName") != null) {
                userBuilder.distinguishedName((String) attrs.get("distinguishedName").get());
            }
            
            // Verificar si la cuenta está habilitada
            // En AD, userAccountControl contiene flags de estado de la cuenta
            boolean accountEnabled = true;
            if (attrs.get("userAccountControl") != null) {
                int userAccountControl = Integer.parseInt((String) attrs.get("userAccountControl").get());
                // Bit 2 (0x2) indica cuenta deshabilitada
                accountEnabled = (userAccountControl & 0x2) == 0;
            }
            userBuilder.accountEnabled(accountEnabled);
            
            return userBuilder.build();
        }
    }


}
