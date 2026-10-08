namespace G4atScanner;

// Ejecución reciente (Prefetch): marca SOLO los .pf cuyo nombre coincide con una
// firma de cheat conocida. No se vuelca el historial completo de ejecución del PC;
// únicamente se comprueba contra la lista de cheats. (La carpeta Prefetch suele
// requerir permisos de administrador para leerse por completo.)
public class RecentExecutionDetector : IDetector
{
    public string Title => "Ejecución reciente";
    public string Sub => "Prefetch · solo coincidencias conocidas";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var prefetch = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(prefetch)) { log("Prefetch no accesible", false); return Task.FromResult(findings); }

        IEnumerable<string> pf;
        try { pf = Directory.EnumerateFiles(prefetch, "*.pf", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { log("Prefetch requiere permisos de administrador", false); return Task.FromResult(findings); }
        catch { return Task.FromResult(findings); }

        int seen = 0;
        foreach (var f in pf)
        {
            seen++;
            // el nombre del .pf es NOMBRE.EXE-HASH.pf
            var name = Path.GetFileNameWithoutExtension(f);
            if (Signatures.MatchesFamily(name))
            {
                var exe = name.Split('-')[0];
                log($"! ejecutado recientemente: {exe}", true);
                findings.Add(new Finding("recent-exec", "suspicious",
                    "Ejecutable de cheat ejecutado recientemente", exe));
            }
        }
        log($"prefetch: {seen} entradas comparadas", false);
        return Task.FromResult(findings);
    }
}
