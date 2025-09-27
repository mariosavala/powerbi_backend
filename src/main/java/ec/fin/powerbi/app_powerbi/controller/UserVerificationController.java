package ec.fin.powerbi.app_powerbi.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.util.*;
@RestController
@RequestMapping("/api/verify")
public class UserVerificationController {

    @Value("${spring.ldap.urls}")
    private String ldapUrl;

    @Value("${spring.ldap.username}")
    private String ldapUsername;

    @Value("${spring.ldap.password}")
    private String ldapPassword;

    @GetMapping("/user/{username}")
    public ResponseEntity<?> verifyUser(@PathVariable String username) {
        Map<String, Object> result = new HashMap<>();

        // Extraer sAMAccountName
        String sAMAccountName = username.contains("@") ? username.substring(0, username.indexOf("@")) : username;

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
            env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
            env.put("java.naming.referral", "follow");

            InitialDirContext context = new InitialDirContext(env);

            // Buscar desde DC=coopsanjose,DC=local
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setCountLimit(10);
            controls.setTimeLimit(10000);

            String searchBase = "DC=coopsanjose,DC=local";
            String[] filters = {
                    "(sAMAccountName=" + sAMAccountName + ")",
                    "(userPrincipalName=" + username + ")",
                    "(mail=" + username + ")"
            };

            boolean userFound = false;
            Map<String, Object> userInfo = null;

            for (String filter : filters) {
                try {
                    NamingEnumeration<SearchResult> results = context.search(searchBase, filter, controls);

                    if (results.hasMore()) {
                        SearchResult sr = results.next();
                        userFound = true;

                        userInfo = new HashMap<>();
                        userInfo.put("dn", sr.getNameInNamespace());
                        userInfo.put("found_with_filter", filter);

                        Attributes attrs = sr.getAttributes();
                        Map<String, String> attributes = new HashMap<>();

                        String[] importantAttrs = {"sAMAccountName", "userPrincipalName", "mail",
                                "displayName", "givenName", "sn", "userAccountControl", "description","physicalDeliveryOfficeName"};

                        for (String attrName : importantAttrs) {
                            Attribute attr = attrs.get(attrName);
                            if (attr != null) {
                                try {
                                    attributes.put(attrName, attr.get().toString());
                                } catch (Exception e) {
                                    attributes.put(attrName, "Error reading");
                                }
                            }
                        }

                        // Procesar el estado del usuario basado en userAccountControl
                        Attribute uacAttr = attrs.get("userAccountControl");
                        if (uacAttr != null) {
                            try {
                                int userAccountControl = Integer.parseInt(uacAttr.get().toString());
                                Map<String, Object> accountStatus = new HashMap<>();

                                // Bit 2 (0x0002) = Account disabled
                                boolean isEnabled = (userAccountControl & 2) == 0;
                                accountStatus.put("enabled", isEnabled);
                                accountStatus.put("status", isEnabled ? "ACTIVO" : "DESHABILITADO");

                                // Otros flags importantes del userAccountControl
                                Map<String, Boolean> flags = new HashMap<>();
                                flags.put("account_disabled", (userAccountControl & 0x0002) != 0);
                                flags.put("password_never_expires", (userAccountControl & 0x10000) != 0);
                                flags.put("password_expired", (userAccountControl & 0x800000) != 0);
                                flags.put("account_locked", (userAccountControl & 0x0010) != 0);
                                flags.put("normal_account", (userAccountControl & 0x0200) != 0);

                                accountStatus.put("flags", flags);
                                accountStatus.put("userAccountControl_value", userAccountControl);

                                // Descripción del estado
                                if (!isEnabled) {
                                    accountStatus.put("description", "La cuenta está deshabilitada y no puede iniciar sesión");
                                } else if ((userAccountControl & 0x800000) != 0) {
                                    accountStatus.put("description", "La cuenta está activa pero la contraseña ha expirado");
                                } else if ((userAccountControl & 0x0010) != 0) {
                                    accountStatus.put("description", "La cuenta está bloqueada");
                                } else {
                                    accountStatus.put("description", "La cuenta está activa y funcional");
                                }

                                userInfo.put("account_status", accountStatus);

                            } catch (NumberFormatException e) {
                                Map<String, Object> errorStatus = new HashMap<>();
                                errorStatus.put("error", "No se pudo interpretar userAccountControl");
                                errorStatus.put("raw_value", uacAttr.get().toString());
                                userInfo.put("account_status", errorStatus);
                            }
                        } else {
                            Map<String, Object> unknownStatus = new HashMap<>();
                            unknownStatus.put("status", "DESCONOCIDO");
                            unknownStatus.put("description", "No se encontró el atributo userAccountControl");
                            userInfo.put("account_status", unknownStatus);
                        }

                        userInfo.put("attributes", attributes);
                        break;
                    }

                } catch (Exception e) {
                    result.put("error_filter_" + filter, e.getMessage());
                }
            }

            result.put("user_exists", userFound);
            result.put("search_username", sAMAccountName);
            result.put("original_username", username);
            result.put("search_base", searchBase);

            if (userFound && userInfo != null) {
                result.put("user_info", userInfo);
            }

            if (!userFound) {
                // Buscar usuarios similares
                try {
                    String similarFilter = "(sAMAccountName=" + sAMAccountName.substring(0, Math.min(3, sAMAccountName.length())) + "*)";
                    NamingEnumeration<SearchResult> similarResults = context.search(searchBase, similarFilter, controls);

                    List<String> similarUsers = new ArrayList<>();
                    while (similarResults.hasMore() && similarUsers.size() < 5) {
                        SearchResult sr = similarResults.next();
                        Attributes attrs = sr.getAttributes();
                        Attribute samAttr = attrs.get("sAMAccountName");
                        if (samAttr != null) {
                            similarUsers.add(samAttr.get().toString());
                        }
                    }

                    if (!similarUsers.isEmpty()) {
                        result.put("similar_users", similarUsers);
                    }

                } catch (Exception e) {
                    result.put("similar_search_error", e.getMessage());
                }
            }

            context.close();
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            result.put("connection_error", e.getMessage());
            return ResponseEntity.status(500).body(result);
        }
    }
}