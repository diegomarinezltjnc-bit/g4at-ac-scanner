using System.Text;
using Microsoft.Win32;

namespace G4atScanner;

// Evidencia de ejecución extra: MUICache y UserAssist guardan nombres de
// programas que se han abierto (aunque ya se hayan borrado). Se comparan SOLO
// contra firmas de cheats conocidas; no se vuelca el historial completo.
public class ExecutionEvidenceDetector : IDetector
{
    public string Title => "Evidencia de ejecución";
    public string Sub => "MUICache · UserAssist";

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        int seen = 0;

        // 1) MUICache — nombres de ejecutables lanzados
        try
        {
            using var mui = Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
            if (mui != null)
            {
                foreach (var v in mui.GetValueNames())
                {
                    seen++;
                    var name = Path.GetFileName(v);
                    var sev = Signatures.Severity(name) ?? (Signatures.LooksLikeCheatRpf(name) ? "suspicious" : null);
                    if (sev != null)
                    {
                        log($"! MUICache: {name}", true);
                        findings.Add(new Finding("exec-evidence", sev,
                            "Cheat lanzado (MUICache)", name));
                    }
                }
            }
        }
        catch { }

        // 2) UserAssist — programas abiertos desde el Explorador (ROT13)
        try
        {
            using var ua = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (ua != null)
            {
                foreach (var guid in ua.GetSubKeyNames())
                {
                    using var count = ua.OpenSubKey(Path.Combine(guid, "Count"));
                    if (count == null) continue;
                    foreach (var v in count.GetValueNames())
                    {
                        seen++;
                        var name = Rot13(v);
                        var leaf = Path.GetFileName(name);
                        var sev = Signatures.Severity(leaf);
                        if (sev != null)
                        {
                            log($"! UserAssist: {leaf}", true);
                            findings.Add(new Finding("exec-evidence", sev,
                                "Cheat ejecutado (UserAssist)", leaf));
                        }
                    }
                }
            }
        }
        catch { }

        if (findings.Count == 0) log($"sin evidencia de ejecución de cheats ({seen} entradas)", false);
        return Task.FromResult(findings);
    }

    static string Rot13(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c is >= 'a' and <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c is >= 'A' and <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
