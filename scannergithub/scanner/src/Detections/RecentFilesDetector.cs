namespace G4atScanner;

// Archivos recientes: Windows guarda accesos directos (.lnk) a lo último que el
// usuario abrió (carpeta Recent + Jump Lists). El NOMBRE del acceso directo
// revela archivos de cheat o .rpf abiertos aunque ya se hayan borrado.
// Match-only: solo se mira el nombre, nunca se abre el archivo apuntado.
public class RecentFilesDetector : IDetector
{
    public string Title => "Archivos recientes";
    public string Sub => "accesos directos a cheats / .rpf";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var recent = Path.Combine(roaming, "Microsoft", "Windows", "Recent");
        if (!Directory.Exists(recent)) { log("carpeta Recent no accesible", false); return Task.FromResult(findings); }

        IEnumerable<string> lnks;
        try { lnks = Directory.EnumerateFiles(recent, "*.lnk", SearchOption.AllDirectories); }
        catch { return Task.FromResult(findings); }

        int seen = 0;
        foreach (var f in lnks)
        {
            seen++;
            var name = Path.GetFileNameWithoutExtension(f);   // = nombre del archivo abierto
            var sev = Signatures.Severity(name);
            var rpf = Signatures.LooksLikeCheatRpf(name);
            if (sev != null || rpf)
            {
                log($"! archivo reciente: {name}", true);
                findings.Add(new Finding("recent-files", sev ?? "suspicious",
                    "Archivo de cheat abierto recientemente", name));
            }
        }
        if (findings.Count == 0) log($"archivos recientes sin coincidencias ({seen})", false);
        return Task.FromResult(findings);
    }
}
