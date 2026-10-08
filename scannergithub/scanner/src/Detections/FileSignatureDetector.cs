namespace G4atScanner;

// Archivos con nombre de cheat en carpetas de riesgo. SOLO reporta archivos cuyo
// nombre coincide con una firma conocida; no lista ni envía el resto de archivos.
public class FileSignatureDetector : IDetector
{
    public string Title => "Firmas de cheats en disco";
    public string Sub => "nombres conocidos en carpetas de riesgo";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var prof = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var folders = new[]
        {
            Path.Combine(prof, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        int seen = 0;
        foreach (var folder in folders.Distinct())
        {
            if (!Directory.Exists(folder)) continue;
            IEnumerable<string> files;
            try
            {
                // nivel superior + un nivel de subcarpetas (acotado, para no barrer todo el disco)
                files = Directory.EnumerateFiles(folder, "*", SearchOption.TopDirectoryOnly)
                    .Concat(SafeSubFiles(folder))
                    .Take(4000);
            }
            catch { continue; }

            foreach (var f in files)
            {
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (!Signatures.RiskExtensions.Contains(ext)) continue;
                seen++;
                var name = Path.GetFileName(f);
                var sev = Signatures.Severity(name);
                if (sev != null)
                {
                    log($"! archivo: {name}", true);
                    findings.Add(new Finding("signatures", sev, "Archivo con nombre de cheat conocido", name));
                }
            }
        }
        log($"disco: {seen} archivos comparados", false);
        return Task.FromResult(findings);
    }

    static IEnumerable<string> SafeSubFiles(string folder)
    {
        IEnumerable<string> subs;
        try { subs = Directory.EnumerateDirectories(folder).Take(60); }
        catch { yield break; }
        foreach (var d in subs)
        {
            IEnumerable<string> fs;
            try { fs = Directory.EnumerateFiles(d, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }
            foreach (var f in fs) yield return f;
        }
    }
}
