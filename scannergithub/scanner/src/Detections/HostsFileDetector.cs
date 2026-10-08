namespace G4atScanner;

// Archivo hosts: algunos cheats lo editan para BLOQUEAR los servidores de FiveM/
// Cfx (y así evitar baneos o telemetría) o para redirigir la autenticación.
// Se marcan SOLO las líneas que redirigen dominios oficiales de FiveM/Cfx o
// dominios de cheat. No se vuelca el archivo entero.
public class HostsFileDetector : IDetector
{
    public string Title => "Archivo hosts";
    public string Sub => "bloqueos a FiveM / Cfx";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var hosts = Path.Combine(win, "System32", "drivers", "etc", "hosts");
        if (!File.Exists(hosts)) { log("archivo hosts no encontrado", false); return Task.FromResult(findings); }

        string[] lines;
        try { lines = File.ReadAllLines(hosts); }
        catch { log("archivo hosts no accesible", false); return Task.FromResult(findings); }

        int active = 0;
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            active++;
            var low = line.ToLowerInvariant();

            // ¿redirige un dominio oficial de FiveM/Cfx? -> intento de bloqueo
            if (Signatures.BlockedTargets.Any(t => low.Contains(t)))
            {
                log($"! hosts bloquea FiveM/Cfx: {line}", true);
                findings.Add(new Finding("hosts", "critical",
                    "El archivo hosts bloquea/redirige servidores de FiveM/Cfx", line));
            }
            // ¿apunta a un dominio de cheat? -> redirección de autenticación
            else if (Signatures.MatchesDomain(low))
            {
                log($"! hosts con dominio de cheat: {line}", true);
                findings.Add(new Finding("hosts", "suspicious",
                    "El archivo hosts referencia un dominio de cheat", line));
            }
        }
        if (findings.Count == 0) log($"archivo hosts limpio ({active} entradas activas)", false);
        return Task.FromResult(findings);
    }
}
