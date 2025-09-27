package ec.fin.powerbi.app_powerbi.service.security;

import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Component;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.util.Hashtable;

@Component
@Slf4j
public class LdapDiagnosticTool {

    @Autowired
    private LdapTemplate ldapTemplate;

    @Value("${spring.ldap.urls}")
    private String ldapUrl;

    @Value("${spring.ldap.username}")
    private String ldapUsername;

    @Value("${spring.ldap.password}")
    private String ldapPassword;

    /**
     * Método para diagnosticar la estructura LDAP completa
     */
    public void performCompleteDiagnostic() {
        log.info("🔍 === INICIANDO DIAGNÓSTICO COMPLETO DE LDAP ===");

        // 1. Probar conexión directa sin Spring LDAP
        testDirectConnection();

        // 2. Descubrir el Base DN correcto
        discoverBaseDN();

        // 3. Probar diferentes bases
        testDifferentBases();

        // 4. Buscar el usuario específico en toda la estructura
        searchUserEverywhere("msavala");
    }

    /**
     * Test de conexión directa usando JNDI
     */
    private void testDirectConnection() {
        log.info("🔌 Probando conexión directa con JNDI...");

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
            env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
            env.put("java.naming.referral", "follow");
            env.put("com.sun.jndi.ldap.connect.timeout", "10000");

            InitialDirContext context = new InitialDirContext(env);
            log.info("✅ Conexión directa exitosa");

            // Obtener información del contexto raíz
            Attributes rootAttrs = context.getAttributes("");
            log.info("📋 Atributos del contexto raíz:");

            NamingEnumeration<? extends Attribute> attrs = rootAttrs.getAll();
            while (attrs.hasMore()) {
                Attribute attr = attrs.next();
                log.info("   - {}: {}", attr.getID(), attr.get());
            }

            context.close();

        } catch (Exception e) {
            log.error("❌ Error en conexión directa: {}", e.getMessage(), e);
        }
    }

    /**
     * Descubrir el Base DN correcto
     */
    private void discoverBaseDN() {
        log.info("🔍 Descubriendo Base DN correcto...");

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
            env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
            env.put("java.naming.referral", "follow");

            InitialDirContext context = new InitialDirContext(env);

            // Buscar en el contexto raíz
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.ONELEVEL_SCOPE);

            NamingEnumeration<SearchResult> results = context.search("", "(objectClass=*)", searchControls);

            log.info("📁 Objetos encontrados en el contexto raíz:");
            while (results.hasMore()) {
                SearchResult result = results.next();
                String dn = result.getNameInNamespace();
                log.info("   - DN: {}", dn);

                // Mostrar algunos atributos importantes
                Attributes attrs = result.getAttributes();
                Attribute objectClass = attrs.get("objectClass");
                if (objectClass != null) {
                    log.info("     ObjectClass: {}", objectClass.get());
                }
            }

            context.close();

        } catch (Exception e) {
            log.error("❌ Error descubriendo Base DN: {}", e.getMessage(), e);
        }
    }

    /**
     * Probar diferentes posibles Base DN
     */
    private void testDifferentBases() {
        log.info("🧪 Probando diferentes Base DN...");

        String[] possibleBases = {
                "",
                "DC=coopsanjose,DC=local",
                "DC=local",
                "DC=coopsanjose",
                "O=coopsanjose",
                "CN=Configuration,DC=coopsanjose,DC=local",
                "CN=Schema,CN=Configuration,DC=coopsanjose,DC=local"
        };

        for (String baseDN : possibleBases) {
            try {
                log.info("🔍 Probando Base DN: '{}'", baseDN.isEmpty() ? "[ROOT]" : baseDN);

                Hashtable<String, String> env = new Hashtable<>();
                env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                env.put(Context.PROVIDER_URL, ldapUrl + (baseDN.isEmpty() ? "" : "/" + baseDN));
                env.put(Context.SECURITY_AUTHENTICATION, "simple");
                env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
                env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
                env.put("java.naming.referral", "follow");

                InitialDirContext context = new InitialDirContext(env);

                // Contar objetos en este nivel
                SearchControls searchControls = new SearchControls();
                searchControls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
                searchControls.setCountLimit(10);

                NamingEnumeration<SearchResult> results = context.search("", "(objectClass=*)", searchControls);

                int count = 0;
                while (results.hasMore() && count < 5) {
                    SearchResult result = results.next();
                    String dn = result.getNameInNamespace();
                    log.info("   ✅ Objeto encontrado: {}", dn);
                    count++;
                }

                log.info("   📊 Total aproximado de objetos: {}", count >= 5 ? "5+" : count);
                context.close();

            } catch (Exception e) {
                log.warn("   ❌ Base DN '{}' no funciona: {}", baseDN, e.getMessage());
            }
        }
    }

    /**
     * Buscar usuario en toda la estructura disponible
     */
    private void searchUserEverywhere(String username) {
        log.info("👤 Buscando usuario '{}' en toda la estructura...", username);

        String[] basesToSearch = {
                "",
                "DC=coopsanjose,DC=local",
                "CN=Users,DC=coopsanjose,DC=local",
                "OU=Users,DC=coopsanjose,DC=local",
                "OU=SEGURIDAD DE LA INFORMACION,DC=coopsanjose,DC=local"
        };

        String[] userFilters = {
                "(sAMAccountName=" + username + ")",
                "(sAMAccountName=" + username + "*)",
                "(cn=" + username + ")",
                "(cn=" + username + "*)",
                "(name=" + username + "*)",
                "(displayName=*" + username + "*)"
        };

        for (String baseDN : basesToSearch) {
            for (String filter : userFilters) {
                try {
                    log.debug("🔍 Buscando en base '{}' con filtro '{}'",
                            baseDN.isEmpty() ? "[ROOT]" : baseDN, filter);

                    Hashtable<String, String> env = new Hashtable<>();
                    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                    env.put(Context.PROVIDER_URL, ldapUrl);
                    env.put(Context.SECURITY_AUTHENTICATION, "simple");
                    env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
                    env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
                    env.put("java.naming.referral", "follow");

                    InitialDirContext context = new InitialDirContext(env);

                    SearchControls searchControls = new SearchControls();
                    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                    searchControls.setCountLimit(10);
                    searchControls.setTimeLimit(10000);

                    NamingEnumeration<SearchResult> results = context.search(baseDN, filter, searchControls);

                    while (results.hasMore()) {
                        SearchResult result = results.next();
                        String dn = result.getNameInNamespace();

                        Attributes attrs = result.getAttributes();
                        String samAccount = getAttributeValue(attrs, "sAMAccountName");
                        String displayName = getAttributeValue(attrs, "displayName");
                        String userPrincipal = getAttributeValue(attrs, "userPrincipalName");

                        log.info("🎯 USUARIO ENCONTRADO!");
                        log.info("   DN: {}", dn);
                        log.info("   sAMAccountName: {}", samAccount);
                        log.info("   userPrincipalName: {}", userPrincipal);
                        log.info("   displayName: {}", displayName);
                        log.info("   Base utilizado: {}", baseDN.isEmpty() ? "[ROOT]" : baseDN);
                        log.info("   Filtro utilizado: {}", filter);
                    }

                    context.close();

                } catch (Exception e) {
                    log.debug("❌ Error buscando en '{}' con '{}': {}", baseDN, filter, e.getMessage());
                }
            }
        }
    }

    private String getAttributeValue(Attributes attributes, String attributeName) {
        try {
            Attribute attribute = attributes.get(attributeName);
            return attribute != null ? attribute.get().toString() : "null";
        } catch (Exception e) {
            return "error";
        }
    }
}