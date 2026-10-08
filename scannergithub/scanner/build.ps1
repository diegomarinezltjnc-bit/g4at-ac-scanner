# Compila el scanner en un solo .exe autocontenido (Windows x64).
# Requiere: .NET 8 SDK  (https://dotnet.microsoft.com/download/dotnet/8.0)
# Uso:  pwsh ./build.ps1   (o en PowerShell normal:  ./build.ps1)

dotnet publish g4at-scanner.csproj -c Release -r win-x64 `
  -p:PublishSingleFile=true -p:SelfContained=true `
  -p:IncludeNativeLibrariesForSelfExtract=true

Write-Host ""
Write-Host "Listo. El .exe está en:  bin\Release\net8.0-windows\win-x64\publish\g4at-ac-scanner.exe"
