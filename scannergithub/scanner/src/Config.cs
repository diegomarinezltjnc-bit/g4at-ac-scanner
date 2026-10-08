using System.Text.Json;
using System.Reflection;

namespace G4atScanner;

// Configuración del scanner.
//  - serverUrl / licenseKey: se hornean al construir el .exe de cada cliente
//    (config.json embebido), o se leen de un config.json junto al .exe.
//  - caseCode: viene del enlace de descarga (argumento de línea de comandos),
//    o de un archivo "case.cfg" junto al .exe. Así el sospechoso solo abre y escanea.
public class AppConfig
{
    public string ServerUrl { get; set; } = "";
    public string LicenseKey { get; set; } = "";
    public string ClientVersion { get; set; } = "1.0.0";
    public string CaseCode { get; set; } = "";

    public static AppConfig Load(string[] args)
    {
        var cfg = new AppConfig();

        // 1) config embebido en el .exe (recomendado para producción)
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("config.json"));
            if (name != null)
            {
                using var s = asm.GetManifestResourceStream(name)!;
                using var r = new StreamReader(s);
                Merge(cfg, r.ReadToEnd());
            }
        }
        catch { /* sin config embebido */ }

        // 2) config.json junto al .exe (sobreescribe)
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "config.json");
            if (File.Exists(path)) Merge(cfg, File.ReadAllText(path));
        }
        catch { }

        // 3) código de caso: argumento  (p.ej.  g4at-ac-scanner.exe GC-7X42)
        var argCode = args.FirstOrDefault(a => a.StartsWith("GC-", StringComparison.OrdinalIgnoreCase));
        if (argCode != null) cfg.CaseCode = argCode.ToUpperInvariant();

        // 4) o del PROPIO NOMBRE del .exe  (p.ej.  g4at-ac-GC7X42.exe  ->  GC-7X42)
        //    Así el enlace de descarga del panel entrega el .exe ya "marcado" con
        //    el caso y el sospechoso solo tiene que hacer doble clic.
        if (string.IsNullOrEmpty(cfg.CaseCode))
        {
            try
            {
                var exeName = Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "");
                var m = System.Text.RegularExpressions.Regex.Match(
                    exeName, "GC[-_]?([A-Za-z0-9]{4})",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (m.Success) cfg.CaseCode = "GC-" + m.Groups[1].Value.ToUpperInvariant();
            }
            catch { }
        }

        // 5) o archivo case.cfg junto al .exe (lo incluye el enlace de descarga)
        if (string.IsNullOrEmpty(cfg.CaseCode))
        {
            try
            {
                var p = Path.Combine(AppContext.BaseDirectory, "case.cfg");
                if (File.Exists(p)) cfg.CaseCode = File.ReadAllText(p).Trim().ToUpperInvariant();
            }
            catch { }
        }

        return cfg;
    }

    static void Merge(AppConfig cfg, string json)
    {
        var doc = JsonSerializer.Deserialize<AppConfig>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (doc == null) return;
        if (!string.IsNullOrWhiteSpace(doc.ServerUrl)) cfg.ServerUrl = doc.ServerUrl.TrimEnd('/');
        if (!string.IsNullOrWhiteSpace(doc.LicenseKey)) cfg.LicenseKey = doc.LicenseKey;
        if (!string.IsNullOrWhiteSpace(doc.ClientVersion)) cfg.ClientVersion = doc.ClientVersion;
        if (!string.IsNullOrWhiteSpace(doc.CaseCode)) cfg.CaseCode = doc.CaseCode;
    }
}
