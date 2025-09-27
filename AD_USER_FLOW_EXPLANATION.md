# 🔍 Explicación del Flujo de Usuarios en Active Directory

## 👥 **Dos tipos de usuarios diferentes:**

### **1. Usuario de Servicio (Service Account)**
```yaml
# En application.yml
username: cn=service-account,ou=Service Accounts,dc=coopsanjose,dc=local
password: ${LDAP_PASSWORD:SJti2.0*2022}
```

**Propósito:** Solo para que la aplicación pueda **CONSULTAR** el Active Directory.
**NO es para login de usuarios finales.**

### **2. Usuarios Finales (Empleados de tu empresa)**
- Ejemplos: `msavala`, `juan.perez`, `admin@coopsanjose.local`
- Estos son los que se van a autenticar en tu aplicación

---

## 🔄 **Flujo Completo de Autenticación:**

```
┌─────────────────────────────────────────────────────────────┐
│ 1. USUARIO FINAL hace login                                 │
│    POST /api/auth/login                                     │
│    {"username": "msavala", "password": "su_contraseña"}     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. APLICACIÓN usa USUARIO DE SERVICIO para BUSCAR          │
│    → ¿Existe "msavala" en AD?                               │
│    → ¿Está activo?                                          │
│    → ¿En qué grupos está?                                   │
│    → ¿Cuál es su DN (Distinguished Name)?                   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. APLICACIÓN autentica CON CREDENCIALES DEL USUARIO FINAL │
│    → Conecta al AD con: DN del usuario + su contraseña     │
│    → Si es correcto = ✅ Usuario autenticado                │
│    → Si es incorrecto = ❌ Error de credenciales            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. APLICACIÓN genera tokens JWT                            │
│    → accessToken (para acceder a la API)                   │
│    → refreshToken (para renovar el access token)           │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚙️ **Configuración Actual (lo que tienes):**

### **Active Directory:**
```yaml
ad:
  domain: coopsanjose.local
  url: ldap://csjdc01.coopsanjose.local:389
  search-base: dc=coopsanjose,dc=local
  user-search-base: dc=coopsanjose,dc=local  # ← Busca en TODA la base
  user-search-filter: (&(objectClass=user)(|(sAMAccountName={0})(mail={0})(userPrincipalName={0})))
  group-search-base: dc=coopsanjose,dc=local
  service-user: cn=service-account,ou=Service Accounts,dc=coopsanjose,dc=local  # ← USUARIO DE SERVICIO
  service-password: ${AD_SERVICE_PASSWORD:SJti2.0*2022}
```

### **Tipos de login soportados:**
- **Username**: `msavala`
- **Email**: `msavala@coopsanjose.local`
- **UPN**: `msavala@coopsanjose.local`

---

## 🚨 **Error Actual - Código 49:**

```
LDAP: error code 49 - 80090308: LdapErr: DSID-0C090527, comment: AcceptSecurityContext error, data 52e, v4563
```

**Significado:** El usuario de servicio `service-account` no tiene permisos para hacer búsquedas en el AD.

---

## ✅ **Soluciones posibles:**

### **Opción 1: Verificar permisos del usuario de servicio**
El usuario `service-account` necesita:
- ✅ **Read** permissions en `dc=coopsanjose,dc=local`
- ✅ **List Contents** permissions 
- ✅ **Read All Properties** permissions

### **Opción 2: Usar un usuario administrador temporal**
Puedes cambiar temporalmente a:
```yaml
service-user: cn=Administrator,cn=Users,dc=coopsanjose,dc=local
service-password: ${AD_SERVICE_PASSWORD:password_del_administrador}
```

### **Opción 3: Crear nuevo usuario de servicio**
Crear un nuevo usuario en AD con permisos específicos para lectura.

---

## 🔧 **Para probar si funciona:**

1. **Verificar conectividad:**
   ```bash
   # Desde tu servidor
   telnet csjdc01.coopsanjose.local 389
   ```

2. **Probar con usuario real:**
   ```bash
   curl -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"tu_usuario_real","password":"tu_password_real"}'
   ```

---

## 📋 **Resumen:**

- ✅ **Usuario de Servicio**: Solo para consultas (service-account)
- ✅ **Usuarios Finales**: Los empleados que se van a loguear
- ✅ **No necesitas "relacionar" usuarios**: El AD ya los tiene
- 🚨 **Problema actual**: Permisos del usuario de servicio
- ✅ **Búsqueda**: En todas las OUs sin discriminar
- ✅ **Login**: Por username, email o UPN
