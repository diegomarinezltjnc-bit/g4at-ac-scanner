# g4at·ac — Scanner (cliente .exe)

Programa de Windows que el sospechoso descarga y abre. Escanea su equipo en busca
de **evidencia de trampas de FiveM**, muestra el progreso con animaciones y, al
terminar, envía el resultado a tu panel y se cierra solo.

La interfaz es la misma que te enseñé (negro espacio + estrellas), renderizada con
WebView2; la lógica de escaneo y el envío a la API van en C#.

## Requisitos para compilar
- Windows + **.NET 8 SDK**.
- WebView2 Runtime (viene de serie en Windows 10/11 modernos).

## Compilar
```powershell
cd scanner
./build.ps1
```
Sale un único `g4at-ac-scanner.exe` en `bin/Release/net8.0-windows/win-x64/publish/`.

## Configuración (`config.json`)
Antes de compilar, pon tu servidor y la licencia:
```json
{ "serverUrl": "https://tu-panel.com", "licenseKey": "XXXX-XXXX-XXXX-XXXX", "clientVersion": "1.0.0" }
```
Se hornea dentro del `.exe`. Cada servidor/cliente compila su build con su licencia.

## El código de caso (que el sospechoso no tiene que escribir)
El `.exe` toma el código de caso de, en este orden:
1. un argumento:  `g4at-ac-scanner.exe GC-7X42`
2. un archivo `case.cfg` junto al `.exe` (una sola línea con el código).

**Flujo recomendado:** en el panel creas el caso → te da `GC-XXXX` → le pasas al
sospechoso el `.exe` + el código (o un `.zip` con el `.exe` y un `case.cfg` dentro).
Así él solo abre y escanea. Más adelante el panel puede generar ese `.zip` solo.

## Qué detecta (20 módulos — escaneo forense a fondo)

**FiveM / juego**
- **Procesos en ejecución** compatibles con familias de cheats.
- **Ventanas abiertas** con título de mod menu conocido.
- **Módulos cargados en FiveM** (inyecciones en el proceso del juego).
- **Recursos de FiveM** (inyectores `.asi` / `.dll` en `plugins` y junto al juego, ignorando componentes legítimos).
- **Archivos de juego `.rpf`** — cualquier `.rpf`/`.meta` dentro de la carpeta `mods` de FiveM es un archivo de juego reemplazado (aimbot, munición infinita, sin retroceso, daño…) y se reporta; si el nombre delata la trampa sube a crítico. También `.rpf`/`.asi` sueltos en Descargas/Escritorio/Documentos.
- **Logs de FiveM** (`CitizenFX.log`) — menciones de cheats o señales de inyección/manipulación.

**Archivos y firmas**
- **Archivos sin firma** dentro de FiveM.
- **Firmas de cheats en disco** (Descargas, Escritorio, Documentos, Temp, AppData…).
- **KeyAuth** — rastros de la autenticación que usan muchos cheats de FiveM.

**Red**
- **Caché DNS** — conexiones recientes a dominios de cheats / KeyAuth.
- **Archivo hosts** — bloqueos/redirecciones de los servidores de FiveM/Cfx o a dominios de cheat.

**Evidencia de ejecución (forense)**
- **Ejecución reciente** (Prefetch) — coincidencias con cheats.
- **Actividad reciente (BAM)** — ejecutables registrados por Windows.
- **PcaClient** — últimos programas abiertos.
- **Evidencia de ejecución** (MUICache / UserAssist) — cheats lanzados aunque ya se borraran.
- **Archivos recientes** (.lnk) — cheats o `.rpf` abiertos recientemente.

**Sistema**
- **Servicios del sistema** detenidos (DPS, Sysmain, DiagTrack, PcaSvc).
- **Arranque automático** (Run, carpeta de inicio, tareas programadas).
- **Exclusiones de Windows Defender** — carpetas de riesgo ocultadas al antivirus.
- **Papelera** — archivos de cheat borrados (lee el nombre original).

Todo es **match-only**: solo reporta coincidencias con cheats, nunca archivos
personales. El escaneo se toma su tiempo a propósito (revisa con calma).

> **Cobertura máxima:** BAM, Prefetch, PcaClient, las exclusiones de Defender y
> la Papelera dan más resultados con **permisos de administrador**. Si quieres que
> siempre pida admin, cambia en `app.manifest` el nivel a `requireAdministrator`.

Las firmas (nombres/hashes) se amplían desde el panel sin recompilar.

## Límites del diseño (a propósito)
Para que ningún antivirus lo marque como *stealer* y para no romper reglas de Cfx,
el cliente **no** hace nada de esto: no lee `lsass` ni credenciales, no vuelca el
historial del navegador ni datos personales, no recupera archivos borrados del
usuario, y no se oculta ni evita su cierre. Solo reporta **evidencia de trampas**.

## Firma del .exe (más adelante)
Sin firmar, Windows SmartScreen mostrará un aviso la primera vez. Cuando quieras,
se firma con un certificado de code-signing para quitar ese aviso.
