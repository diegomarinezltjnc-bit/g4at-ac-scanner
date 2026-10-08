using System.Security.Cryptography.X509Certificates;

namespace G4atScanner;

// Módulos SIN FIRMA DIGITAL dentro de la carpeta de FiveM. Los cheats casi nunca
// van firmados; un .dll/.asi sin firma inyectado en el juego es una señal fuerte.
// Se limita a la carpeta del juego (no se escanea el disco entero del usuario).
public class UnsignedFileDetector : IDetector
{
    public string Title => "Archivos sin firma";
    public string Sub => "módulos no firmados en FiveM";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var root = Path.Combine(local, "FiveM", "FiveM.app");
        if (!Directory.Exists(root)) { log("FiveM no instalado en esta cuenta", false); return Task.FromResult(findings); }

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories)
                .Concat(Directory.EnumerateFiles(root, "*.asi", SearchOption.AllDirectories))
                .Take(500); // tope de seguridad
        }
        catch { return Task.FromResult(findings); }

        int checkd = 0;
        foreach (var f in files)
        {
            checkd++;
            if (IsSigned(f)) continue;
            var name = Path.GetFileName(f);
            log($"~ sin firma: {name}", false);
            findings.Add(new Finding("unsigned", "suspicious",
                "Módulo sin firma digital en FiveM", name));
        }
        log($"firmas verificadas: {checkd} módulos", false);
        return Task.FromResult(findings);
    }

    static bool IsSigned(string path)
    {
        try { X509Certificate.CreateFromSignedFile(path); return true; }
        catch { return false; }
    }
}
