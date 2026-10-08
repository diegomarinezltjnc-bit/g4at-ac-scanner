using Microsoft.Win32;

namespace G4atScanner;

// Exclusiones de Windows Defender: los cheaters casi siempre añaden la carpeta
// del cheat (o Descargas/Escritorio/FiveM) a las exclusiones del antivirus para
// que no lo borre. Una exclusión sobre esas rutas es una señal MUY fuerte.
// Leer estas claves suele requerir administrador / sin Tamper Protection.
public class DefenderExclusionDetector : IDetector
{
    public string Title => "Exclusiones de Defender";
    public string Sub => "carpetas ocultadas al antivirus";

    // rutas que NO tienen por qué estar excluidas en un PC limpio
    static readonly string[] Risky =
    {
        "download", "desktop", "escritorio", "temp", "appdata", "fivem",
        "users\\public", "roaming", "\\new folder", "\\cheat", "\\menu"
    };

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var keys = new[]
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        };

        int seen = 0;
        foreach (var path in keys)
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(path);
                if (k == null) continue;
                foreach (var excl in k.GetValueNames())
                {
                    seen++;
                    var low = excl.ToLowerInvariant();
                    var byName = Signatures.Severity(excl) != null;
                    var risky = Risky.Any(r => low.Contains(r));
                    if (byName || risky)
                    {
                        log($"! exclusión sospechosa: {excl}", true);
                        findings.Add(new Finding("defender", byName ? "critical" : "suspicious",
                            byName ? "Exclusión de Defender sobre un cheat conocido"
                                   : "Exclusión de Defender sobre carpeta de riesgo",
                            excl));
                    }
                }
            }
            catch (System.Security.SecurityException) { log("exclusiones requieren administrador", false); }
            catch { }
        }
        if (findings.Count == 0) log($"sin exclusiones sospechosas ({seen} revisadas)", false);
        return Task.FromResult(findings);
    }
}
