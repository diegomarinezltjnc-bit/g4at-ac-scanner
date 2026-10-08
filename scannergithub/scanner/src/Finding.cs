namespace G4atScanner;

// Un hallazgo = evidencia de trampa. Solo se envían estos datos al panel,
// nunca archivos personales ni contenido ajeno a trampas.
public record Finding(
    string Category,   // processes | fivem-modules | fivem-resources | unsigned | signatures | recent-exec
    string Severity,   // critical | suspicious | info
    string Title,
    string? Detail = null
);

// Progreso que el motor reporta a la interfaz.
public record ScanProgress(
    int Percent,
    string PhaseTitle,
    string PhaseSub,
    int PhaseIndex,
    int PhaseTotal,
    string? LogLine = null,
    bool LogFlag = false
);
