using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;

namespace G4atScanner;

// Cliente HTTP contra el panel (API). Solo dos llamadas:
//   validate  -> comprueba licencia + caso antes de escanear
//   submit    -> envía los hallazgos al terminar
public class Api
{
    // IP directa del servidor, usada SOLO como respaldo si el DNS del equipo del
    // sospechoso aún no resuelve g4atac.shop (dominio nuevo / caché lenta del ISP).
    // La conexión por IP mantiene el host original (g4atac.shop) para SNI/Host y
    // validación del certificado, así que el TLS sigue siendo válido: NO se baja
    // la seguridad, solo se evita el fallo de resolución de nombres.
    const string FallbackIp = "66.29.148.192";

    readonly HttpClient _http;
    readonly AppConfig _cfg;

    public Api(AppConfig cfg)
    {
        _cfg = cfg;

        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(12),
            ConnectCallback = async (ctx, ct) =>
            {
                var host = ctx.DnsEndPoint.Host;
                var port = ctx.DnsEndPoint.Port;
                try
                {
                    // intento normal: resolver el dominio por DNS
                    var sock = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    await sock.ConnectAsync(host, port, ct);
                    return new NetworkStream(sock, ownsSocket: true);
                }
                catch (Exception) when (!ct.IsCancellationRequested)
                {
                    // el DNS falló (Host desconocido) o no se pudo conectar:
                    // reintentamos por la IP directa. El TLS posterior usa el host
                    // original, por lo que el certificado de g4atac.shop valida bien.
                    var sock = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    await sock.ConnectAsync(IPAddress.Parse(FallbackIp), port, ct);
                    return new NetworkStream(sock, ownsSocket: true);
                }
            }
        };

        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

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
