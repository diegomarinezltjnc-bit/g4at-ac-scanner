namespace G4atScanner;

// Logs de FiveM: el propio cliente deja constancia de recursos cargados, errores
// de inyección y módulos. Se leen los .log y se marcan SOLO las líneas que
// coinciden con firmas de cheats conocidas o con señales de inyección.
// Match-only sobre el contenido del log del juego (no datos personales).
public class FiveMLogDetector : IDetector
{
    public string Title => "Logs de FiveM";
    public string Sub => "CitizenFX.log · inyecciones y módulos";

    static readonly string[] InjectSignals =
    {
        "injected", "inject", "unknown module", "unsigned module",
        "failed to verify", "tampered", "modified game", "hooking",
        "detour", "d3d11 hook", "overlay inject"
    };

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var app = Path.Combine(local, "FiveM", "FiveM.app");

        var logDirs = new[] { app, Path.Combine(app, "logs"), Path.Combine(app, "data", "cache") };
        var files = new List<string>();
        foreach (var d in logDirs)
        {
            if (!Directory.Exists(d)) continue;
            try { files.AddRange(Directory.EnumerateFiles(d, "*.log", SearchOption.TopDirectoryOnly)); }
            catch { }
        }
        if (files.Count == 0) { log("sin logs de FiveM", false); return Task.FromResult(findings); }

        int lines = 0;
        var reported = new HashSet<string>();
        foreach (var f in files.Distinct())
        {
            IEnumerable<string> content;
            try { content = ReadTail(f, 4000); }
            catch { continue; }

            foreach (var raw in content)
            {
                lines++;
                var line = raw.Trim();
                if (line.Length == 0) continue;
                var low = line.ToLowerInvariant();

                var sev = Signatures.Severity(line);
                if (sev != null)
                {
                    var key = "f:" + line;
                    if (reported.Add(key))
                    {
                        log($"! log FiveM (cheat): {Trim(line)}", true);
                        findings.Add(new Finding("fivem-log", sev,
                            "Cheat mencionado en el log de FiveM", Trim(line)));
                    }
                    continue;
                }
                if (InjectSignals.Any(s => low.Contains(s)))
                {
                    var key = "i:" + low;
                    if (reported.Add(key))
                    {
                        log($"! log FiveM (inyección): {Trim(line)}", true);
                        findings.Add(new Finding("fivem-log", "suspicious",
                            "Señal de inyección/manipulación en el log de FiveM", Trim(line)));
                    }
                }
            }
        }
        if (findings.Count == 0) log($"logs de FiveM limpios ({lines} líneas)", false);
        return Task.FromResult(findings);
    }

    // lee solo las últimas N líneas para no cargar logs enormes
    static IEnumerable<string> ReadTail(string file, int max)
    {
        var all = File.ReadLines(file).ToList();
        return all.Count <= max ? all : all.Skip(all.Count - max);
    }

    static string Trim(string s) => s.Length > 120 ? s[..120] + "…" : s;
}
