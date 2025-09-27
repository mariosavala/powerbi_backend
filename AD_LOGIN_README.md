# Sistema de Login con Active Directory - Spring Boot

Este sistema implementa autenticación contra Active Directory usando Spring Boot, Spring Security, LDAP y JWT tokens.

## 🚀 Características

- ✅ Autenticación contra Active Directory/LDAP
- ✅ Validación de usuarios activos/inactivos
- ✅ Generación de JWT tokens y refresh tokens
- ✅ No requiere persistencia de usuarios en base de datos
- ✅ Manejo completo de errores y validaciones
- ✅ CORS configurado
- ✅ Endpoints de API REST

## 📋 Configuración Requerida

### 1. Variables de Entorno

Configura estas variables de entorno antes de ejecutar la aplicación:

```bash
# Configuración LDAP/Active Directory
AD_SERVICE_PASSWORD=tu-password-servicio-ad
LDAP_PASSWORD=tu-password-servicio-ad

# Configuración JWT (recomendado generar una clave más segura)
JWT_SECRET=tu-clave-secreta-jwt-base64-codificada
```

### 2. Configuración en application.yml

Actualiza los valores en `src/main/resources/application.yml`:

```yaml
spring:
  ldap:
    urls: ldap://tu-servidor-ad.empresa.com:389  # URL de tu servidor AD
    base: dc=empresa,dc=com                       # Base DN de tu dominio
    username: cn=service-account,ou=Service Accounts,dc=empresa,dc=com  # Usuario de servicio
    password: ${LDAP_PASSWORD:password}

ad:
  domain: empresa.com                             # Dominio de AD
  url: ldap://tu-servidor-ad.empresa.com:389
  search-base: dc=empresa,dc=com
  user-search-base: ou=Users,dc=empresa,dc=com   # Donde están los usuarios
  user-search-filter: (sAMAccountName={0})       # Filtro de búsqueda de usuarios
  group-search-base: ou=Groups,dc=empresa,dc=com # Donde están los grupos
  service-user: cn=service-account,ou=Service Accounts,dc=empresa,dc=com
  service-password: ${AD_SERVICE_PASSWORD:password}
```

### 3. Generar Clave JWT Segura

Para generar una clave JWT segura en Base64:

```bash
# Usando OpenSSL
openssl rand -base64 64

# O usando PowerShell
[System.Convert]::ToBase64String((1..64 | ForEach-Object { Get-Random -Maximum 256 }))
```

## 🔧 Instalación y Ejecución

1. **Clonar y navegar al proyecto:**
   ```bash
   cd "C:\Users\msavala\Documents\Proyectos Spring Boot\app-powerbi\app-powerbi"
   ```

2. **Configurar variables de entorno:**
   ```bash
   # Windows PowerShell
   $env:JWT_SECRET = "tu-clave-jwt-base64"
   $env:AD_SERVICE_PASSWORD = "password-servicio-ad"
   $env:LDAP_PASSWORD = "password-servicio-ad"
   ```

3. **Compilar y ejecutar:**
   ```bash
   ./mvnw clean compile
   ./mvnw spring-boot:run
   ```

## 📚 API Endpoints

### 🔐 Autenticación

#### POST /api/auth/login
Autentica un usuario contra Active Directory.

**Request:**
```json
{
  "username": "usuario",
  "password": "contraseña"
}
```

**Nota:** El campo `username` puede ser cualquiera de estos formatos:
- **sAMAccountName**: `usuario`
- **Email**: `usuario@coopsanjose.local`
- **UserPrincipalName**: `usuario@coopsanjose.local`

**Response (Success):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 86400,
  "userInfo": {
    "username": "usuario",
    "displayName": "Nombre Completo",
    "email": "usuario@empresa.com",
    "department": "Departamento",
    "enabled": true,
    "roles": ["ROLE_USER", "ROLE_ADMIN"],
    "groups": ["Administrators", "Users"]
  }
}
```

#### POST /api/auth/refresh
Renueva un token JWT usando el refresh token.

**Request:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:** Mismo formato que login.

#### GET /api/auth/validate
Valida un token JWT.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response:**
```json
{
  "valid": true,
  "username": "usuario",
  "remainingTimeSeconds": 82800,
  "timestamp": "2024-01-01T10:00:00"
}
```

#### POST /api/auth/logout
Confirma el logout (el token debe ser eliminado del cliente).

**Response:**
```json
{
  "message": "Logout exitoso",
  "timestamp": "2024-01-01T10:00:00"
}
```

## 🛠️ Estructura del Proyecto

```
src/main/java/ec/fin/powerbi/app_powerbi/
├── controller/
│   └── AuthController.java              # Endpoints de autenticación
├── dto/
│   ├── LoginRequest.java                # DTO para solicitud de login
│   ├── LoginResponse.java               # DTO para respuesta de login
│   ├── RefreshTokenRequest.java         # DTO para refresh token
│   └── ErrorResponse.java               # DTO para errores
├── persistence/model/
│   └── Users.java                       # Modelo de usuario (sin persistencia)
├── service/security/
│   ├── ActiveDirectoryAuthService.java  # Servicio de autenticación AD
│   ├── JwtService.java                  # Servicio de manejo JWT
│   ├── JwtAuthenticationFilter.java     # Filtro de autenticación JWT
│   └── AppConfig.java                   # Configuración de seguridad
└── exception/
    └── GlobalExceptionHandler.java      # Manejo global de excepciones
```

## 🔍 Troubleshooting

### Error: "Usuario no encontrado"
- Verificar la configuración LDAP en `application.yml`
- Comprobar que el usuario existe en Active Directory
- Validar el `user-search-base` y `user-search-filter`

### Error: "Credenciales inválidas"
- Verificar que la contraseña es correcta
- Comprobar que la cuenta del usuario está habilitada en AD
- Revisar los logs para detalles específicos

### Error de conexión LDAP
- Verificar la URL del servidor AD
- Comprobar conectividad de red
- Validar credenciales del usuario de servicio
- Revisar firewall y puertos (389 para LDAP, 636 para LDAPS)

### Error JWT
- Verificar que `JWT_SECRET` está configurado correctamente
- Comprobar que la clave está en formato Base64
- Validar fechas de expiración

## 🔧 Configuración de Desarrollo

Para desarrollo local, puedes usar configuraciones de prueba:

```yaml
# application-dev.yml
ad:
  url: ldap://localhost:10389  # Para un servidor LDAP local de pruebas
  domain: example.com
  # ... otras configuraciones de desarrollo
```

## 📋 Validaciones Implementadas

- ✅ Usuario existe en Active Directory
- ✅ Cuenta de usuario está activa (userAccountControl)
- ✅ Credenciales son válidas
- ✅ Token JWT no ha expirado
- ✅ Formato de token es válido
- ✅ Validación de entrada de datos

## 🚀 Siguiente Pasos

1. **Configurar HTTPS** para producción
2. **Implementar rate limiting** en endpoints de autenticación
3. **Agregar métricas y monitoring**
4. **Configurar cache** para consultas LDAP frecuentes
5. **Implementar logout server-side** con blacklist de tokens

## 📞 Soporte

Para problemas o preguntas:
1. Revisar logs de la aplicación
2. Verificar configuración de AD
3. Comprobar conectividad de red
4. Validar variables de entorno
