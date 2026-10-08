namespace G4atScanner;

// KeyAuth: API de autenticación que usan MUCHOS cheats de FiveM para validar
// licencias. Su rastro (carpetas/archivos "KeyAuth", DLLs de su SDK) en el PC
// es una señal fuerte de que se ejecutó un cheat con esa protección.
// Match-only: solo se mira el nombre/ruta, nunca el contenido.
public class KeyAuthDetector : IDetector
{
    public string Title => "KeyAuth";
    public string Sub => "rastros de autenticación de cheats";

    static readonly string[] Needles = { "keyauth", "key-auth", "key_auth" };

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var prof = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var dirs = new[]
        {
            Path.Combine(local, "Temp"), local, roaming,
            Path.Combine(prof, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        int seen = 0;
        foreach (var dir in dirs.Distinct())
        {
            if (!Directory.Exists(dir)) continue;
            IEnumerable<string> entries;
            try
            {
                entries = Directory.EnumerateFileSystemEntries(dir, "*", SearchOption.TopDirectoryOnly)
                    .Concat(SafeSub(dir)).Take(5000);
            }
            catch { continue; }

            foreach (var e in entries)
            {
                seen++;
                var name = Path.GetFileName(e).ToLowerInvariant();
                if (Needles.Any(n => name.Contains(n)))
                {
                    log($"! rastro de KeyAuth: {Path.GetFileName(e)}", true);
                    findings.Add(new Finding("keyauth", "critical",
                        "Rastro de KeyAuth (autenticación de cheats)", Path.GetFileName(e)));
                }
            }
        }
        if (findings.Count == 0) log($"sin rastros de KeyAuth ({seen} revisados)", false);
        return Task.FromResult(findings);
    }

    static IEnumerable<string> SafeSub(string dir)
    {
        IEnumerable<string> subs;
        try { subs = Directory.EnumerateDirectories(dir).Take(80); }
        catch { yield break; }
        foreach (var d in subs)
        {
            string[] fs;
            try { fs = Directory.GetFileSystemEntries(d); }
            catch { continue; }
            foreach (var f in fs) yield return f;
        }
    }
}
