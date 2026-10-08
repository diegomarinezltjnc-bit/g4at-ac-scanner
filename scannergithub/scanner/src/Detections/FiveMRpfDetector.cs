namespace G4atScanner;

// Archivos de juego de FiveM (.rpf) modificados para hacer trampa.
//
// Por qué: FiveM NO guarda ningún .rpf dentro de la carpeta "mods"; esa
// carpeta solo existe cuando alguien METE archivos de juego reemplazados
// (los famosos .rpf de aimbot / daño / munición infinita / sin retroceso).
// Por eso CUALQUIER .rpf dentro de "mods" es una modificación del juego y se
// reporta; si además el nombre delata la trampa, sube a crítico.
//
// Match-only: solo se mira el nombre y la ruta del archivo, nunca su contenido.
public class FiveMRpfDetector : IDetector
{
    public string Title => "Archivos de juego (.rpf)";
    public string Sub => "modificaciones de FiveM: aimbot, munición infinita…";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var app = Path.Combine(local, "FiveM", "FiveM.app");

        // 1) La carpeta "mods": cualquier .rpf/.meta/.dat aquí = juego modificado.
        var mods = Path.Combine(app, "mods");
        if (Directory.Exists(mods))
        {
            log("inspeccionando carpeta mods de FiveM", false);
            int n = 0;
            foreach (var f in SafeFiles(mods, SearchOption.AllDirectories))
            {
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (ext is not (".rpf" or ".meta" or ".dat" or ".ydr" or ".ymt" or ".ytd")) continue;
                n++;
                var name = Path.GetFileName(f);
                var hard = Signatures.LooksLikeCheatRpf(name);
                log($"! archivo de juego modificado: {name}", true);
                findings.Add(new Finding("fivem-rpf", hard ? "critical" : "suspicious",
                    hard ? "Archivo de juego de cheat (.rpf) en FiveM"
                         : "Archivo de juego reemplazado dentro de FiveM",
                    RelMods(f)));
            }
            if (n == 0) log("carpeta mods sin archivos de juego reemplazados", false);
        }
        else log("FiveM sin carpeta mods (sin reemplazos)", false);

        // 2) .rpf/.asi sueltos con nombre de cheat en carpetas de descarga habituales.
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var loose = new[]
        {
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
        foreach (var dir in loose)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var f in SafeFiles(dir, SearchOption.TopDirectoryOnly))
            {
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (ext is not (".rpf" or ".asi")) continue;
                var name = Path.GetFileName(f);
                if (ext == ".rpf" || Signatures.LooksLikeCheatRpf(name) || Signatures.MatchesFamily(name))
                {
                    var hard = Signatures.LooksLikeCheatRpf(name) || Signatures.MatchesFamily(name);
                    log($"! archivo de trampa suelto: {name}", true);
                    findings.Add(new Finding("fivem-rpf", hard ? "critical" : "suspicious",
                        "Archivo de modificación de FiveM descargado",
                        $"{name}  ·  {Path.GetDirectoryName(dir)?.Split(Path.DirectorySeparatorChar).LastOrDefault()}/{Path.GetFileName(dir)}"));
                }
            }
        }

        return Task.FromResult(findings);
    }

    static IEnumerable<string> SafeFiles(string root, SearchOption opt)
    {
        try { return Directory.EnumerateFiles(root, "*", opt); }
        catch { return Enumerable.Empty<string>(); }
    }

    static string RelMods(string f)
    {
        var i = f.IndexOf("mods", StringComparison.OrdinalIgnoreCase);
        return i >= 0 ? f[i..] : Path.GetFileName(f);
    }
}
