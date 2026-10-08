using System.Runtime.InteropServices;
using System.Text;

namespace G4atScanner;

// Ventanas abiertas: muchos mod menus tienen un título de ventana con su nombre.
// Se comparan los títulos SOLO contra firmas de cheats conocidas.
public class WindowTitleDetector : IDetector
{
    public string Title => "Ventanas abiertas";
    public string Sub => "títulos compatibles con mod menus";

    delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc cb, IntPtr p);
    [DllImport("user32.dll")] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);

    public Task<List<Finding>> RunAsync(Action<string, bool> log)
    {
        var findings = new List<Finding>();
        int seen = 0;
        try
        {
            EnumWindows((h, _) =>
            {
                if (!IsWindowVisible(h)) return true;
                var sb = new StringBuilder(256);
                if (GetWindowText(h, sb, sb.Capacity) > 0)
                {
                    seen++;
                    var title = sb.ToString();
                    var sev = Signatures.Severity(title);
                    if (sev != null)
                    {
                        log($"! ventana: {title}", true);
                        findings.Add(new Finding("window", sev, "Ventana de cheat abierta", title));
                    }
                }
                return true;
            }, IntPtr.Zero);
        }
        catch { }
        log($"ventanas: {seen} revisadas", false);
        return Task.FromResult(findings);
    }
}
