using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace G4atScanner;

// Cliente HTTP contra el panel (API). Solo dos llamadas:
//   validate  -> comprueba licencia + caso antes de escanear
//   submit    -> envía los hallazgos al terminar
public class Api
{
    readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
    readonly AppConfig _cfg;

    public Api(AppConfig cfg) { _cfg = cfg; }

    public record ValidateResult(bool Ok, string? Error, string? ServerName);
    public record SubmitResult(bool Ok, string? Error, string? ResultToken);

    public async Task<ValidateResult> ValidateAsync()
    {
        try
        {
            var r = await _http.PostAsJsonAsync($"{_cfg.ServerUrl}/api/scan/validate",
                new { license_key = _cfg.LicenseKey, case_code = _cfg.CaseCode });
            var json = await r.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.GetProperty("ok").GetBoolean())
                return new(true, null, root.TryGetProperty("server_name", out var s) ? s.GetString() : null);
            return new(false, root.TryGetProperty("error", out var e) ? e.GetString() : "error", null);
        }
        catch (Exception ex) { return new(false, "sin conexión: " + ex.Message, null); }
    }

    public async Task<SubmitResult> SubmitAsync(IEnumerable<Finding> findings, string startedAtIso)
    {
        try
        {
            var payload = new
            {
                license_key = _cfg.LicenseKey,
                case_code = _cfg.CaseCode,
                client_ver = _cfg.ClientVersion,
                started_at = startedAtIso,
                findings = findings.Select(f => new
                {
                    category = f.Category,
                    severity = f.Severity,
                    title = f.Title,
                    detail = f.Detail
                })
            };
            var r = await _http.PostAsJsonAsync($"{_cfg.ServerUrl}/api/scan/submit", payload);
            var json = await r.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.GetProperty("ok").GetBoolean())
                return new(true, null, root.TryGetProperty("result_token", out var t) ? t.GetString() : null);
            return new(false, root.TryGetProperty("error", out var e) ? e.GetString() : "error", null);
        }
        catch (Exception ex) { return new(false, "sin conexión: " + ex.Message, null); }
    }
}
