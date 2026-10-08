using System.Diagnostics;

namespace G4atScanner;

// Módulos cargados en FiveM: marca DLLs inyectadas con nombre de cheat conocido.
// Es detección anti-trampa estándar sobre el propio proceso del juego.
public class FiveMModuleDetector : IDetector
{
    public string Title => "Módulos cargados en FiveM";
    public string Sub => "inyecciones en el proceso del juego";

    static readonly string[] GameProcs = { "FiveM", "FiveM_GTAProcess", "FiveM_b2802_GTAProcess", "CitizenFX" };

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        var game = Process.GetProcesses()
            .FirstOrDefault(p => GameProcs.Any(g => string.Equals(p.ProcessName, g, StringComparison.OrdinalIgnoreCase))
                                 || p.ProcessName.Contains("GTAProcess", StringComparison.OrdinalIgnoreCase));
        if (game == null) { log("FiveM no está abierto", false); return Task.FromResult(findings); }

        log($"analizando módulos de {game.ProcessName} (pid {game.Id})", false);
        try
        {
            foreach (ProcessModule m in game.Modules)
            {
                var file = m.ModuleName ?? "";
                if (Signatures.MatchesFamily(file))
                {
                    log($"! módulo inyectado: {file}", true);
                    findings.Add(new Finding("fivem-modules", "critical",
                        "Módulo de cheat inyectado en FiveM", file));
                }
            }
        }
        catch (Exception ex) { log("no se pudieron leer todos los módulos: " + ex.Message, false); }
        return Task.FromResult(findings);
    }
}
