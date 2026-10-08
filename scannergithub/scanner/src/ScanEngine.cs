namespace G4atScanner;

// Orquesta los detectores en secuencia y reporta el progreso a la UI.
public class ScanEngine
{
    // Orden de análisis. Cuantos más módulos, más a fondo (y más tarda, a propósito).
    readonly List<IDetector> _detectors = new()
    {
        // --- FiveM / juego ---
        new ProcessDetector(),
        new WindowTitleDetector(),
        new FiveMModuleDetector(),
        new FiveMResourceDetector(),
        new FiveMRpfDetector(),
        new FiveMLogDetector(),
        // --- archivos y firmas ---
        new UnsignedFileDetector(),
        new FileSignatureDetector(),
        new KeyAuthDetector(),
        // --- red ---
        new DnsCacheDetector(),
        new HostsFileDetector(),
        // --- evidencia de ejecución (forense) ---
        new RecentExecutionDetector(),
        new BamDetector(),
        new PcaClientDetector(),
        new ExecutionEvidenceDetector(),
        new RecentFilesDetector(),
        // --- sistema ---
        new ServicesDetector(),
        new StartupDetector(),
        new DefenderExclusionDetector(),
        new RecycleBinDetector(),
    };

    public IReadOnlyList<Finding> Findings => _all;
    readonly List<Finding> _all = new();

    // onProgress recibe cada actualización para pintarla en la interfaz HTML.
    public async Task RunAsync(Action<ScanProgress> onProgress)
    {
        int total = _detectors.Count;
        for (int i = 0; i < total; i++)
        {
            var det = _detectors[i];
            int basePct = (int)(i / (double)total * 100);
            onProgress(new ScanProgress(basePct, det.Title, det.Sub, i + 1, total));

            var found = new List<Finding>();
            try
            {
                found = await det.RunAsync((line, flag) =>
                    onProgress(new ScanProgress(
                        basePct + (int)(0.5 / total * 100),
                        det.Title, det.Sub, i + 1, total, line, flag)));
            }
            catch (Exception ex)
            {
                onProgress(new ScanProgress(basePct, det.Title, det.Sub, i + 1, total,
                    "error en módulo: " + ex.Message, false));
            }

            _all.AddRange(found);
            // pausa deliberada: el escaneo se toma su tiempo y revisa con calma
            await Task.Delay(900);
            int donePct = (int)((i + 1) / (double)total * 100);
            onProgress(new ScanProgress(donePct, det.Title, det.Sub, i + 1, total,
                $"✓ {det.Title.ToLowerInvariant()} ({found.Count} hallazgos)", false));
        }
        onProgress(new ScanProgress(100, "Escaneo completado", "enviando resultado…", total, total));
    }

    public int Critical => _all.Count(f => f.Severity == "critical");
    public int Suspicious => _all.Count(f => f.Severity == "suspicious");
    public int Reviewed => _all.Count;
}
