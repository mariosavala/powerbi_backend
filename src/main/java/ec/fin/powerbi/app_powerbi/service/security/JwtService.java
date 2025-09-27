package ec.fin.powerbi.app_powerbi.service.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;


    // Extrae el username del token usando el sujeto (subject)
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Método genérico para extraer claims
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Obtiene todos los claims del token
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Genera un token JWT para el usuario
     * @param userDetails Detalles del usuario
     * @return Token JWT
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Genera un token JWT con claims adicionales
     * @param extraClaims Claims adicionales
     * @param userDetails Detalles del usuario
     * @return Token JWT
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + expiration);

        // Agregar información adicional al token
        extraClaims.put("authorities", userDetails.getAuthorities());
        extraClaims.put("enabled", userDetails.isEnabled());
        extraClaims.put("accountNonExpired", userDetails.isAccountNonExpired());
        extraClaims.put("accountNonLocked", userDetails.isAccountNonLocked());
        extraClaims.put("credentialsNonExpired", userDetails.isCredentialsNonExpired());

        try {
            return Jwts.builder()
                    .setClaims(extraClaims)
                    .setSubject(userDetails.getUsername())
                    .setIssuedAt(now)
                    .setExpiration(expirationDate)
                    .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                    .compact();
        } catch (Exception e) {
            log.error("Error generando token JWT: {}", e.getMessage());
            throw new RuntimeException("Error generando token JWT", e);
        }
    }

    // Genera un refreshToken JWT
    public String generateRefreshToken(UserDetails userDetails) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("token_type", "refreshToken"); // Identificador de tipo

        claims.put("authorities", userDetails.getAuthorities());
        claims.put("enabled", userDetails.isEnabled());
        claims.put("accountNonExpired", userDetails.isAccountNonExpired());
        claims.put("accountNonLocked", userDetails.isAccountNonLocked());
        claims.put("credentialsNonExpired", userDetails.isCredentialsNonExpired());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())  // Sujeto (usernameApp)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Valida si el token es válido para el usuario
    public boolean isValidToken(String token, UserDetails userDetails) {

        final String username = extractUserName(token);
        return (
                username.equals(userDetails.getUsername()) && !isTokenExpired(token)
        );
    }

    // Verifica si el token ha expirado
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Extrae la fecha de expiración
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Obtiene la clave de firma (segura y en Base64)
    public SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Extrae el tiempo restante de vida del token en segundos
     * @param token Token JWT
     * @return Tiempo restante en segundos
     */
    public long getTokenRemainingTime(String token) {
        try {
            Date expiration = extractExpiration(token);
            Date now = new Date();
            return Math.max(0, (expiration.getTime() - now.getTime()) / 1000);
        } catch (Exception e) {
            log.debug("Error calculando tiempo restante del token: {}", e.getMessage());
            return 0;
        }
    }
}
