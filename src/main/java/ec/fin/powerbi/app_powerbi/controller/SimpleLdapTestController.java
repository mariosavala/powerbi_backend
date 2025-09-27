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
@RequestMapping("/api/test")
public class SimpleLdapTestController {

    @Value("${spring.ldap.urls}")
    private String ldapUrl;

    @Value("${spring.ldap.username}")
    private String ldapUsername;

    @Value("${spring.ldap.password}")
    private String ldapPassword;

    @GetMapping("/ldap-structure")
    public ResponseEntity<?> testLdapStructure() {

        Map<String, Object> result = new HashMap<>();

        try {
            // Test básico de conexión
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
            env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
            env.put("java.naming.referral", "follow");

            InitialDirContext context = new InitialDirContext(env);
            result.put("connection", "SUCCESS");

            // Obtener información del naming context
            try {
                Attributes attrs = context.getAttributes("");
                result.put("rootAttributes", extractAttributes(attrs));
            } catch (Exception e) {
                result.put("rootAttributes", "Error: " + e.getMessage());
            }

            // Listar objetos en la raíz
            try {
                SearchControls controls = new SearchControls();
                controls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
                controls.setCountLimit(20);

                NamingEnumeration<SearchResult> results = context.search("", "(objectClass=*)", controls);
                List<Map<String, String>> objects = new ArrayList<>();

                while (results.hasMore()) {
                    SearchResult sr = results.next();
                    Map<String, String> obj = new HashMap<>();
                    obj.put("dn", sr.getNameInNamespace());
                    obj.put("name", sr.getName());

                    // Obtener objectClass
                    Attributes objAttrs = sr.getAttributes();
                    Attribute ocAttr = objAttrs.get("objectClass");
                    if (ocAttr != null) {
                        obj.put("objectClass", ocAttr.get().toString());
                    }

                    objects.add(obj);
                }

                result.put("rootObjects", objects);

            } catch (Exception e) {
                result.put("rootObjects", "Error: " + e.getMessage());
            }

            // Buscar contextos de naming comunes
            String[] commonContexts = {
                    "DC=coopsanjose,DC=local",
                    "DC=local",
                    "CN=Configuration",
                    "CN=Schema",
                    "CN=Users"
            };

            Map<String, Object> contextTests = new HashMap<>();
            for (String contextDN : commonContexts) {
                try {
                    Attributes contextAttrs = context.getAttributes(contextDN);
                    contextTests.put(contextDN, "EXISTS");
                } catch (Exception e) {
                    contextTests.put(contextDN, "NOT_FOUND: " + e.getMessage());
                }
            }
            result.put("contextTests", contextTests);

            context.close();

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            result.put("error", e.getMessage());
            result.put("connection", "FAILED");
            return ResponseEntity.status(500).body(result);
        }
    }

    @GetMapping("/search-user/{username}")
    public ResponseEntity<?> searchSpecificUser(@PathVariable String username) {
        Map<String, Object> result = new HashMap<>();

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
            env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
            env.put("java.naming.referral", "follow");

            InitialDirContext context = new InitialDirContext(env);

            // Extraer solo el nombre de usuario si viene con formato email
            String searchUsername = username.contains("@") ? username.substring(0, username.indexOf("@")) : username;

            // Búsqueda amplia desde la raíz
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setCountLimit(50);
            controls.setTimeLimit(15000);

            // Diferentes filtros
            String[] filters = {
                    "(sAMAccountName=" + searchUsername + ")",
                    "(cn=" + searchUsername + ")",
                    "(name=" + searchUsername + ")",
                    "(displayName=*" + searchUsername + "*)",
                    "(userPrincipalName=" + username + ")",
                    "(mail=" + username + ")"
            };

            List<Map<String, Object>> foundUsers = new ArrayList<>();

            for (String filter : filters) {
                try {
                    NamingEnumeration<SearchResult> results = context.search("", filter, controls);

                    while (results.hasMore()) {
                        SearchResult sr = results.next();
                        Map<String, Object> user = new HashMap<>();
                        user.put("dn", sr.getNameInNamespace());
                        user.put("filter_used", filter);
                        user.put("attributes", extractAttributes(sr.getAttributes()));

                        foundUsers.add(user);
                    }

                } catch (Exception e) {
                    result.put("filter_" + filter, "Error: " + e.getMessage());
                }
            }

            result.put("users_found", foundUsers);
            result.put("search_username", searchUsername);
            result.put("original_username", username);

            context.close();

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            result.put("error", e.getMessage());
            return ResponseEntity.status(500).body(result);
        }
    }

    private Map<String, Object> extractAttributes(Attributes attrs) {
        Map<String, Object> result = new HashMap<>();
        try {
            NamingEnumeration<? extends Attribute> allAttrs = attrs.getAll();
            while (allAttrs.hasMore()) {
                Attribute attr = allAttrs.next();
                String id = attr.getID();
                try {
                    Object value = attr.get();
                    result.put(id, value.toString());
                } catch (Exception e) {
                    result.put(id, "Error reading value");
                }
            }
        } catch (Exception e) {
            result.put("error", "Error extracting attributes: " + e.getMessage());
        }
        return result;
    }
}
