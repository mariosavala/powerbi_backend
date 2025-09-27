package ec.fin.powerbi.app_powerbi.controller;

import ec.fin.powerbi.app_powerbi.service.powerbi.PowerBiService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;


@RestController
@RequestMapping("/api/powerbi")
public class PowerBiController {

    private final PowerBiService powerBiService;

    public PowerBiController(PowerBiService powerBiService) {
        this.powerBiService = powerBiService;
    }

    @GetMapping("/embedConfig")
    public ResponseEntity<Map<String, Object>> getEmbedConfig() {
        try {
            Map<String, Object> embedConfig = powerBiService.getEmbedConfig();
            return ResponseEntity.ok(embedConfig);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al generar la configuración de Power BI: " + e.getMessage()));
        }
    }
}
