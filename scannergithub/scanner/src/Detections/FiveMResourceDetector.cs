namespace G4atScanner;

// Integridad de FiveM: busca módulos/plugins añadidos a la carpeta del juego
// (inyectores .asi/.dll en plugins/, DLLs sueltas junto al ejecutable) que
// puedan ser inyecciones de cheat. El .rpf lo lleva FiveMRpfDetector aparte.
public class FiveMResourceDetector : IDetector
{
    public string Title => "Recursos de FiveM";
    public string Sub => "plugins e inyecciones en la carpeta del juego";

    // .dll legítimas conocidas que FiveM/Windows cargan (reducen falsos positivos).
    static readonly string[] KnownGood =
    {
        "citizengame.dll", "citizen-", "adhesive.dll", "botan.dll",
        "gtaca.dll", "d3dcompiler", "openvr", "steam_api", "discord",
        "cef", "libcef", "vcruntime", "msvcp", "concrt", "chrome_elf",
        "nvngx", "amd_ags", "reshade", "dxgi.dll", "d3d11.dll"
    };

    static bool IsKnownGood(string name)
    {
        var n = name.ToLowerInvariant();
        foreach (var g in KnownGood) if (n.Contains(g)) return true;
        return false;
    }

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var app = Path.Combine(local, "FiveM", "FiveM.app");
        // también instalaciones que el usuario puso en otro sitio (Cfx carpeta portable)
        var roots = new List<string>
        {
            Path.Combine(app, "plugins"),          // inyectores .asi/.dll (lo más común)
            app,                                   // DLLs sueltas junto al .exe
            Path.Combine(appData, "CitizenFX"),
        };

        int scanned = 0;
        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) continue;
            log($"revisando {Shorten(root)}", false);
            IEnumerable<string> files;
            try
            {
                // plugins puede tener subcarpetas; la raíz de la app solo nivel 1
                var depth = root.EndsWith("plugins") || root.EndsWith("CitizenFX")
                    ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                files = Directory.EnumerateFiles(root, "*", depth);
            }
            catch { continue; }

            foreach (var f in files)
            {
                scanned++;
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (ext is not (".asi" or ".dll")) continue;
                var name = Path.GetFileName(f);
                if (IsKnownGood(name)) continue;   // componente legítimo conocido

                var byName = Signatures.MatchesFamily(name);
                // un .asi en plugins es un inyector externo -> siempre sospechoso.
                var sev = byName ? "critical" : "suspicious";
                log($"! módulo en FiveM: {name}", true);
                findings.Add(new Finding("fivem-resources", sev,
                    byName ? "Plugin de cheat en la carpeta de FiveM"
                           : "Módulo externo inyectable en FiveM",
                    Shorten(f)));
            }
        }

        if (scanned == 0) log("no se encontró instalación de FiveM", false);
        else if (findings.Count == 0) log($"carpeta de FiveM limpia ({scanned} archivos)", false);
        return Task.FromResult(findings);
    }

    static string Shorten(string p)
    {
        var i = p.IndexOf("FiveM.app", StringComparison.OrdinalIgnoreCase);
        return i >= 0 ? p[i..] : p;
    }
}
