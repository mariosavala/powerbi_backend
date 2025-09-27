package ec.fin.powerbi.app_powerbi.service.powerbi;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Service
public class PowerBiService {

    private static final String AUTHORITY = "https://login.microsoftonline.com/%s/oauth2/v2.0/token";
    private static final String SCOPE = "https://analysis.windows.net/powerbi/api/.default";

    @Value("${powerbi.tenantId}")
    private String tenantId;

    @Value("${powerbi.clientId}")
    private String clientId;

    @Value("${powerbi.clientSecret}")
    private String clientSecret;

    @Value("${powerbi.workspaceId}")
    private String workspaceId;

    @Value("${powerbi.reportId}")
    private String reportId;

    /**
     * Obtiene el access token de Azure AD
     */
    public String getAccessToken() throws Exception {
        ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                        clientId,
                        ClientCredentialFactory.createFromSecret(clientSecret))
                .authority(String.format(AUTHORITY, tenantId))
                .build();

        ClientCredentialParameters parameters =
                ClientCredentialParameters.builder(Collections.singleton(SCOPE))
                        .build();

        IAuthenticationResult result = app.acquireToken(parameters).get();
        return result.accessToken();
    }

    /**
     * Obtiene la configuración para embeber el reporte
     */
    public Map<String, Object> getEmbedConfig() throws Exception {
        String token = getAccessToken();
        String datasetId = getDatasetId(token);

        // Endpoint para generar el embed token
        String url = String.format("https://api.powerbi.com/v1.0/myorg/groups/%s/reports/%s/GenerateToken",
                workspaceId, reportId);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Body con reports, datasets y workspace
        Map<String, Object> body = new HashMap<>();
        body.put("accessLevel", "View");
        body.put("reports", List.of(Map.of("id", reportId)));
        body.put("datasets", List.of(Map.of("id", datasetId)));
        body.put("targetWorkspaces", List.of(Map.of("id", workspaceId)));

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.postForEntity(url, entity, Map.class);

        Map<String, Object> embedConfig = new HashMap<>();
        embedConfig.put("embedToken", response.getBody().get("token"));
        embedConfig.put("embedUrl", getEmbedUrl(token));
        embedConfig.put("reportId", reportId);

        return embedConfig;
    }

    /**
     * Obtiene el datasetId del reporte
     */
    private String getDatasetId(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        String url = String.format("https://api.powerbi.com/v1.0/myorg/groups/%s/reports/%s",
                workspaceId, reportId);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);

        HttpEntity<Void> entity = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);

        return (String) response.getBody().get("datasetId");
    }

    /**
     * Obtiene el embedUrl del reporte
     */
    private String getEmbedUrl(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        String url = String.format("https://api.powerbi.com/v1.0/myorg/groups/%s/reports/%s",
                workspaceId, reportId);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);

        HttpEntity<Void> entity = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);

        return (String) response.getBody().get("embedUrl");
    }
}
