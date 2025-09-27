package ec.fin.powerbi.app_powerbi.service.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

import java.util.HashMap;
import java.util.Map;

@Configuration
@Slf4j
public class LdapConfig {

    @Value("${spring.ldap.urls}")
    private String ldapUrl;

    @Value("${spring.ldap.base}")
    private String ldapBase;

    @Value("${spring.ldap.username}")
    private String ldapUsername;

    @Value("${spring.ldap.password}")
    private String ldapPassword;

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();

        // CONFIGURACIÓN BASADA EN EL DIAGNÓSTICO
        contextSource.setUrl(ldapUrl);
        // IMPORTANTE: Usar el defaultNamingContext confirmado
        contextSource.setBase("DC=coopsanjose,DC=local");
        contextSource.setUserDn(ldapUsername);
        contextSource.setPassword(ldapPassword);

        // Configuraciones optimizadas para este AD específico
        Map<String, Object> environmentProperties = new HashMap<>();

        // Configuraciones críticas
        environmentProperties.put("java.naming.referral", "follow");
        environmentProperties.put("java.naming.ldap.referral.limit", "10");
        environmentProperties.put("java.naming.ldap.version", "3");

        // Timeouts
        environmentProperties.put("com.sun.jndi.ldap.connect.timeout", "15000");
        environmentProperties.put("com.sun.jndi.ldap.read.timeout", "30000");

        // Configuraciones específicas para AD
        environmentProperties.put("java.naming.ldap.attributes.binary", "objectGUID objectSid");
        environmentProperties.put("java.naming.ldap.derefAliases", "always");

        // Pool de conexiones
        environmentProperties.put("com.sun.jndi.ldap.connect.pool", "true");
        environmentProperties.put("com.sun.jndi.ldap.connect.pool.maxsize", "10");
        environmentProperties.put("com.sun.jndi.ldap.connect.pool.prefsize", "5");
        environmentProperties.put("com.sun.jndi.ldap.connect.pool.timeout", "300000");

        contextSource.setPooled(true);
        contextSource.setBaseEnvironmentProperties(environmentProperties);
        contextSource.setReferral("follow");

        try {
            contextSource.afterPropertiesSet();
            log.info("LDAP Context configurado exitosamente con Base DN confirmado: DC=coopsanjose,DC=local");
        } catch (Exception e) {
            log.error("Error configurando LDAP Context: {}", e.getMessage(), e);
            throw new RuntimeException("No se pudo configurar LDAP Context", e);
        }

        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        LdapTemplate template = new LdapTemplate(contextSource());
        template.setIgnorePartialResultException(true);
        template.setIgnoreNameNotFoundException(true);
        template.setIgnoreSizeLimitExceededException(true);
        template.setDefaultTimeLimit(30000);
        template.setDefaultCountLimit(100);
        return template;
    }
}