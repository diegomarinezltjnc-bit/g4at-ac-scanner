using System.ServiceProcess;

namespace G4atScanner;

// Servicios de Windows detenidos que los cheaters apagan para borrar rastros
// (DPS, Sysmain, DiagTrack). Que estén parados es una señal de bypass.
public class ServicesDetector : IDetector
{
    public string Title => "Servicios del sistema";
    public string Sub => "DPS · Sysmain · DiagTrack";

    static readonly (string svc, string nice)[] Watch =
    {
        ("DPS", "Diagnostic Policy Service"),
        ("SysMain", "SysMain (Superfetch)"),
        ("DiagTrack", "Connected User Experiences"),
        ("PcaSvc", "Program Compatibility Assistant"),
    };

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        foreach (var (svc, nice) in Watch)
        {
            try
            {
                using var sc = new ServiceController(svc);
                var st = sc.Status;
                if (st != ServiceControllerStatus.Running)
                {
                    log($"~ servicio detenido: {svc}", false);
                    findings.Add(new Finding("services", "suspicious",
                        $"Servicio {svc} detenido", $"{nice} — posible intento de borrar rastros"));
                }
                else log($"{svc} activo", false);
            }
            catch { /* servicio no existe en este Windows */ }
        }
        return Task.FromResult(findings);
    }
}
