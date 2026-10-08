using Microsoft.Win32;

namespace G4atScanner;

// PcaClient (Program Compatibility Assistant): Windows guarda los últimos
// programas ejecutados. Se comparan SOLO contra firmas de cheats conocidas.
// Fuentes: PcaAppLaunchDic.txt y el registro de PCA.
public class PcaClientDetector : IDetector
{
    public string Title => "PcaClient";
    public string Sub => "últimos programas abiertos";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        int seen = 0;

        // 1) archivo PcaAppLaunchDic.txt
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var dic = Path.Combine(win, "appcompat", "pca", "PcaAppLaunchDic.txt");
        try
        {
            if (File.Exists(dic))
            {
                foreach (var line in File.ReadLines(dic))
                {
                    seen++;
                    var path = line.Split('|')[0];
                    var name = Path.GetFileName(path);
                    var sev = Signatures.Severity(name);
                    if (sev != null)
                    {
                        log($"! PCA: {name}", true);
                        findings.Add(new Finding("pcaclient", sev,
                            "Cheat en el historial de PcaClient", name));
                    }
                }
            }
        }
        catch { log("PcaAppLaunchDic no accesible", false); }

        // 2) registro de PCA
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\PCA\PcaGeneralDb0") ??
                Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store");
            if (k != null)
            {
                foreach (var v in k.GetValueNames())
                {
                    seen++;
                    var name = Path.GetFileName(v);
                    var sev = Signatures.Severity(name);
                    if (sev != null)
                    {
                        log($"! PCA (registro): {name}", true);
                        findings.Add(new Finding("pcaclient", sev,
                            "Cheat registrado en PcaClient", name));
                    }
                }
            }
        }
        catch { }

        if (findings.Count == 0) log($"PcaClient sin coincidencias ({seen} entradas)", false);
        return Task.FromResult(findings);
    }
}
