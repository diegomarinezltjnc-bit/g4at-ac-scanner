using System.Reflection;
using System.Text.Json;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace G4atScanner;

// Ventana del scanner: hospeda la interfaz HTML (WebView2) y la controla desde C#.
public class MainForm : Form
{
    readonly AppConfig _cfg;
    readonly WebView2 _web = new();
    readonly string _startedAt = DateTime.UtcNow.ToString("o");

    public MainForm(AppConfig cfg)
    {
        _cfg = cfg;
        // ventana limpia: sin bordes, siempre encima de todo, no minimizable
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(540, 600);
        BackColor = Color.Black;
        TopMost = true;                 // se sobrepone a todo el escritorio
        ShowInTaskbar = false;          // no aparece en la barra de tareas
        MinimizeBox = false;
        MaximizeBox = false;
        Text = "g4at·ac Scanner";

        _web.Dock = DockStyle.Fill;
        Controls.Add(_web);
        Load += OnLoad;
    }

    // bloquea el minimizar (Win+D, Win+M, etc.): si algo lo minimiza, vuelve al frente
    protected override void OnResize(EventArgs e)
    {
        if (WindowState == FormWindowState.Minimized)
            WindowState = FormWindowState.Normal;
        base.OnResize(e);
    }

    // ignora la orden de minimizar del sistema y mantiene el foco al frente
    const int WM_SYSCOMMAND = 0x0112;
    const int SC_MINIMIZE = 0xF020;
    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_SYSCOMMAND && (m.WParam.ToInt32() & 0xFFF0) == SC_MINIMIZE)
            return; // descarta el minimizar
        base.WndProc(ref m);
    }

    async void OnLoad(object? sender, EventArgs e)
    {
        await _web.EnsureCoreWebView2Async();
        var st = _web.CoreWebView2.Settings;
        st.AreDefaultContextMenusEnabled = false;   // sin menú de clic derecho
        st.IsZoomControlEnabled = false;            // sin zoom
        st.AreBrowserAcceleratorKeysEnabled = false; // sin F5 / Ctrl+ atajos
        st.AreDevToolsEnabled = false;              // sin consola F12
        st.IsStatusBarEnabled = false;
        _web.DefaultBackgroundColor = Color.Black;
        _web.CoreWebView2.NavigationCompleted += async (_, __) => await RunFlow();
        _web.NavigateToString(LoadHtml());
    }

    async Task RunFlow()
    {
        // 1) validar licencia + caso
        if (string.IsNullOrEmpty(_cfg.CaseCode))
        {
            await Js("g4Error('No se recibió el código de caso. Abre el scanner desde el enlace que te dio el staff.')");
            return;
        }
        var api = new Api(_cfg);
        var v = await api.ValidateAsync();
        if (!v.Ok) { await Js($"g4Error({JsonSerializer.Serialize(v.Error ?? "licencia o caso no válido")})"); return; }
        await Js($"g4SetCase({JsonSerializer.Serialize(_cfg.CaseCode)},{JsonSerializer.Serialize(v.ServerName ?? "")})");

        // 2) escanear reportando progreso a la UI
        var engine = new ScanEngine();
        await engine.RunAsync(p =>
        {
            var json = JsonSerializer.Serialize(new
            {
                pct = p.Percent, title = p.PhaseTitle, sub = p.PhaseSub,
                phase = p.PhaseIndex, total = p.PhaseTotal, log = p.LogLine, flag = p.LogFlag
            });
            BeginInvoke(() => _ = Js($"g4Progress({json})"));
        });

        // 3) enviar resultado al panel
        var sr = await api.SubmitAsync(engine.Findings, _startedAt);
        var done = JsonSerializer.Serialize(new
        {
            ok = sr.Ok, token = sr.ResultToken, error = sr.Error,
            critical = engine.Critical, suspicious = engine.Suspicious, reviewed = engine.Reviewed
        });
        await Js($"g4Done({done})");

        // 4) cerrar solo tras una breve pausa
        await Task.Delay(3500);
        Close();
    }

    Task<string> Js(string code) => _web.CoreWebView2.ExecuteScriptAsync(code);

    static string LoadHtml()
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().First(n => n.EndsWith("scanner.html"));
        using var s = asm.GetManifestResourceStream(name)!;
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }
}
