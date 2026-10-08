using Microsoft.Win32;

namespace G4atScanner;

// Arranque automático: entradas de inicio (Run), carpeta de inicio y tareas
// programadas cuyo nombre/ruta coincide con un cheat. Match-only contra firmas.
public class StartupDetector : IDetector
{
    public string Title => "Arranque automático";
    public string Sub => "inicio, Run y tareas programadas";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();

        // 1) claves Run (HKCU + HKLM)
        CheckRun(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", findings, log);
        CheckRun(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", findings, log);

        // 2) carpeta de inicio
        try
        {
            var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (Directory.Exists(startup))
                foreach (var f in Directory.EnumerateFiles(startup))
                {
                    var sev = Signatures.Severity(Path.GetFileName(f));
                    if (sev != null) { log($"! inicio: {Path.GetFileName(f)}", true);
                        findings.Add(new Finding("startup", sev, "Cheat en la carpeta de inicio", Path.GetFileName(f))); }
                }
        }
        catch { }

        // 3) tareas programadas (por nombre de archivo de tarea)
        try
        {
            var tasks = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (Directory.Exists(tasks))
                foreach (var f in Directory.EnumerateFiles(tasks, "*", SearchOption.AllDirectories))
                {
                    var sev = Signatures.Severity(Path.GetFileName(f));
                    if (sev != null) { log($"! tarea: {Path.GetFileName(f)}", true);
                        findings.Add(new Finding("startup", sev, "Tarea programada de cheat", Path.GetFileName(f))); }
                }
        }
        catch { }

        if (findings.Count == 0) log("arranque limpio", false);
        return Task.FromResult(findings);
    }

    static void CheckRun(RegistryKey root, string sub, List<Finding> findings, Action<string, bool> log)
    {
        try
        {
            using var k = root.OpenSubKey(sub);
            if (k == null) return;
            foreach (var name in k.GetValueNames())
            {
                var data = k.GetValue(name)?.ToString() ?? "";
                var sev = Signatures.Severity(name) ?? Signatures.Severity(data);
                if (sev != null) { log($"! run: {name}", true);
                    findings.Add(new Finding("startup", sev, "Cheat en arranque (Run)", name)); }
            }
        }
        catch { }
    }
}
