using System.Text;

namespace G4atScanner;

// Papelera de reciclaje: busca archivos BORRADOS cuyo nombre coincide con un cheat.
// Lee los metadatos ($I) para obtener el nombre original. Solo reporta coincidencias
// con cheats; no toca ni envía archivos personales.
public class RecycleBinDetector : IDetector
{
    public string Title => "Papelera de reciclaje";
    public string Sub => "borrados recientes con nombre de cheat";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        int seen = 0;
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady) continue;
            var binRoot = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
            if (!Directory.Exists(binRoot)) continue;

            IEnumerable<string> iFiles;
            try { iFiles = Directory.EnumerateFiles(binRoot, "$I*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var i in iFiles)
            {
                seen++;
                var original = ReadOriginalName(i);
                if (original == null) continue;
                var sev = Signatures.Severity(Path.GetFileName(original));
                if (sev != null)
                {
                    var name = Path.GetFileName(original);
                    log($"! borrado: {name}", true);
                    findings.Add(new Finding("recyclebin", sev,
                        "Archivo de cheat borrado (papelera)", name));
                }
            }
        }
        log($"papelera: {seen} elementos comparados", false);
        return Task.FromResult(findings);
    }

    // Formato $I (Windows 10): 8 bytes versión, 8 tamaño, 8 fecha, 4 longitud nombre, resto UTF-16
    static string? ReadOriginalName(string path)
    {
        try
        {
            var b = File.ReadAllBytes(path);
            if (b.Length < 28) return null;
            long version = BitConverter.ToInt64(b, 0);
            if (version == 2)
            {
                int len = BitConverter.ToInt32(b, 24);
                if (len <= 0 || 28 + len * 2 > b.Length) return null;
                return Encoding.Unicode.GetString(b, 28, (len - 1) * 2);
            }
            // versión 1: nombre fijo de 260 chars a partir del byte 24
            return Encoding.Unicode.GetString(b, 24, Math.Min(520, b.Length - 24)).TrimEnd('\0');
        }
        catch { return null; }
    }
}
