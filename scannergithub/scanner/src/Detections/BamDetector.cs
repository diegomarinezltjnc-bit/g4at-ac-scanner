using Microsoft.Win32;

namespace G4atScanner;

// Background Activity Moderator (BAM): registro de ejecutables que se han ejecutado.
// Se comparan SOLO contra firmas de cheats conocidas (no se vuelca el historial).
// Suele requerir permisos de administrador para leerse por completo.
public class BamDetector : IDetector
{
    public string Title => "Actividad reciente (BAM)";
    public string Sub => "ejecutables registrados por Windows";

    static readonly string[] BamPaths =
    {
        @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        @"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
    };

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        int seen = 0;
        foreach (var basePath in BamPaths)
        {
            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(basePath);
                if (baseKey == null) continue;
                foreach (var sid in baseKey.GetSubKeyNames())
                {
                    using var sidKey = baseKey.OpenSubKey(sid);
                    if (sidKey == null) continue;
                    foreach (var val in sidKey.GetValueNames())
                    {
                        seen++;
                        var sev = Signatures.Severity(val);
                        if (sev != null)
                        {
                            var name = val.Split('\\').Last();
                            log($"! ejecutado (BAM): {name}", true);
                            findings.Add(new Finding("bam", sev,
                                "Cheat ejecutado recientemente (BAM)", name));
                        }
                    }
                }
            }
            catch (System.Security.SecurityException) { log("BAM requiere administrador", false); }
            catch { }
        }
        log($"BAM: {seen} entradas comparadas", false);
        return Task.FromResult(findings);
    }
}
