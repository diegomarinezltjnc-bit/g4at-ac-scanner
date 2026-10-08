namespace G4atScanner;

// Catálogo de firmas: palabras clave de cheats de FiveM conocidos.
// Es solo una LISTA DE NOMBRES para reconocer rastros; no contiene cheats ni
// instrucciones. En producción se amplía desde el panel (GET /api/signatures)
// para añadir cheats nuevos sin recompilar.
public static class Signatures
{
    // Familias de mod menus / cheats conocidos  -> severidad CRÍTICA
    // (nombres públicos de menús; sirven para reconocer procesos/archivos).
    public static readonly string[] CriticalFamilies =
    {
        // menús FiveM / GTA conocidos
        "eulen", "lynx", "redengine", "red-engine", "hydro", "tzx", "tz-",
        "skript", "skript.gg", "desudo", "impulse", "cherax", "stand",
        "susano", "absolute", "brightside", "disturbed", "fatality",
        "hammafia", "onetap", "dopamine", "hx-menu", "hxmenu", "d3dmenu",
        "nitrous", "crypto-menu", "phantomx", "phantom-x", "paragon",
        "oblivion", "tsunami", "hyperion", "quantum-menu", "saintgang",
        "lexis", "novoline", "ozark", "weston", "luna-menu", "meta-menu",
        "2take1", "kiddions", "xenon-menu", "b4u", "nexus-menu", "forte",
        "guardian-cheat", "haxel", "vortex-menu"
    };

    // Palabras típicas de cheats/bypass  -> severidad SOSPECHOSA
    public static readonly string[] SuspiciousKeywords =
    {
        "cheat", "hack", "aimbot", "silentaim", "silent-aim", "triggerbot",
        "wallhack", "esp-", "-esp", "spoofer", "hwidspoofer", "serialspoofer",
        "hwid-spoof", "hwid_spoof", "bypass", "unban", "modmenu", "mod-menu",
        "mod_menu", "injector", "inject", "cracked", "fivemcheat", "fivem-cheat",
        "gtamenu", "gta-menu", "loader-cheat", "norecoil", "no-recoil",
        "godmode", "god-mode", "magicbullet", "magic-bullet", "rapidfire",
        "unlock-all", "unlockall", "moneydrop", "money-drop", "cleaner-hwid",
        "spoof-clean", "flusher"
    };

    // Palabras típicas en .rpf / archivos de juego modificados para hacer trampa.
    // (infinito, aimbot, daño, etc. — lo que el usuario describió)
    public static readonly string[] CheatRpfKeywords =
    {
        "aimbot", "godmode", "god-mode", "god_mode", "norecoil", "no-recoil",
        "no_recoil", "recoil", "infinite", "infinito", "hitbox", "hit-box",
        "damage", "magicbullet", "magic-bullet", "rapidfire", "rapid-fire",
        "explosive", "stamina", "ammo", "silent", "remove_roll", "removeroll",
        "menyoo", "trainer", "wallhack", "esp", "cheat", "hack", "bypass"
    };

    // Extensiones de riesgo en disco (incluye .rpf: archivos de juego de FiveM).
    public static readonly string[] RiskExtensions =
        { ".dll", ".exe", ".sys", ".asi", ".bin", ".rpf", ".dat" };

    // Dominios asociados a cheats / autenticación de cheats (KeyAuth y tiendas).
    // Se usan para la caché DNS y el archivo hosts. Solo NOMBRES, no enlaces.
    public static readonly string[] CheatDomains =
    {
        "keyauth.win", "keyauth.cc", "keyauth.com", "eulencheats", "eulen.cc",
        "redengine", "hydro.wtf", "disturbed.rip", "tzx", "skript.gg",
        "desudo", "cherax.io", "cherax.pro", "constelia", "fatality.win",
        "onetap", "susano", "impulse.lol", "absolute.gg", "brightside",
        "hx-cheats", "d3dmenu", "nitrous.gg", "dopamine", "paragon.cx",
        "oblivion-services", "lexis.gg", "novoline", "tsunami.gg"
    };

    // Dominios oficiales de FiveM/anticheat que un cheater intenta BLOQUEAR
    // en el archivo hosts (para evitar bans/telemetría). Si aparecen redirigidos
    // a 127.0.0.1/0.0.0.0 es muy sospechoso.
    public static readonly string[] BlockedTargets =
    {
        "cfx.re", "fivem.net", "citizenfx", "forum.cfx.re", "runtime.fivem.net",
        "policy-live.fivem.net", "lambda.fivem.net", "keymaster.fivem.net"
    };

    public static bool MatchesDomain(string? host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        var h = host.ToLowerInvariant();
        foreach (var d in CheatDomains) if (h.Contains(d)) return true;
        return false;
    }

    // Devuelve "critical", "suspicious" o null según el nombre.
    public static string? Severity(string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        var n = name.ToLowerInvariant();
        foreach (var f in CriticalFamilies) if (n.Contains(f)) return "critical";
        foreach (var k in SuspiciousKeywords) if (n.Contains(k)) return "suspicious";
        return null;
    }

    public static bool MatchesFamily(string? name) => Severity(name) != null;

    // ¿El nombre del .rpf (o archivo de juego) sugiere trampa concreta?
    public static bool LooksLikeCheatRpf(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        var n = name.ToLowerInvariant();
        foreach (var k in CheatRpfKeywords) if (n.Contains(k)) return true;
        return false;
    }
}
