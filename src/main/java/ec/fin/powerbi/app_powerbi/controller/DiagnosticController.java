package ec.fin.powerbi.app_powerbi.controller;

import ec.fin.powerbi.app_powerbi.service.security.LdapDiagnosticTool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/diagnostic")
public class DiagnosticController {

    @Autowired
    private LdapDiagnosticTool diagnosticTool;

    @GetMapping("/ldap")
    public ResponseEntity<String> runLdapDiagnostic() {
        try {
            diagnosticTool.performCompleteDiagnostic();
            return ResponseEntity.ok("Diagnóstico completado. Revisa los logs para más detalles.");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error en diagnóstico: " + e.getMessage());
        }
    }

}
