using System.Diagnostics;

namespace G4atScanner;

// Procesos en ejecución: marca los que coinciden con familias de cheats conocidas.
public class ProcessDetector : IDetector
{
    public string Title => "Procesos en ejecución";
    public string Sub => "comparando con firmas de cheats";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch { return Task.FromResult(findings); }

        log($"procesos activos: {procs.Length}", false);
        foreach (var p in procs)
        {
            string name;
            try { name = p.ProcessName; } catch { continue; }
            var sev = Signatures.Severity(name);
            if (sev != null)
            {
                log($"! proceso sospechoso: {name}", true);
                findings.Add(new Finding("processes", sev,
                    "Proceso compatible con cheat en ejecución",
                    $"{name}.exe"));
            }
        }
        return Task.FromResult(findings);
    }
}
