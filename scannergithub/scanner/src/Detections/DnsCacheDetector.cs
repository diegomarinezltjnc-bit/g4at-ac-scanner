using System.Diagnostics;

namespace G4atScanner;

// Caché DNS: lista los dominios que el PC resolvió recientemente y marca SOLO
// los que pertenecen a cheats / webs de autenticación de cheats (KeyAuth, tiendas
// de menús). No se vuelca el historial de navegación; solo coincidencias conocidas.
public class DnsCacheDetector : IDetector
{
    public string Title => "Caché DNS";
    public string Sub => "conexiones a dominios de cheats";

    public async Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        string output;
        try
        {
            var psi = new ProcessStartInfo("ipconfig", "/displaydns")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) { log("no se pudo leer la caché DNS", false); return findings; }
            output = await p.StandardOutput.ReadToEndAsync();
            await p.WaitForExitAsync();
        }
        catch { log("caché DNS no accesible", false); return findings; }

        int seen = 0;
        var hits = new HashSet<string>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            // las líneas de nombre de registro terminan en "----------" arriba; aquí
            // simplemente buscamos cualquier token que parezca dominio.
            if (line.Length == 0) continue;
            if (line.Contains("Record Name") || line.Contains("Nombre de registro") || line.Contains('.'))
            {
                seen++;
                var host = line;
                int c = line.LastIndexOf(':');
                if (c >= 0 && c < line.Length - 1) host = line[(c + 1)..].Trim();
                if (Signatures.MatchesDomain(host) && hits.Add(host.ToLowerInvariant()))
                {
                    log($"! dominio de cheat en DNS: {host}", true);
                    findings.Add(new Finding("dns", "critical",
                        "Conexión reciente a dominio de cheat/KeyAuth", host));
                }
            }
        }
        if (findings.Count == 0) log($"caché DNS limpia ({seen} registros)", false);
        return findings;
    }
}
