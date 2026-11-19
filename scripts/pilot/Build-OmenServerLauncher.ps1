#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Windows .NET Framework C# compiler is missing.' }
$dist = Join-Path $workspace 'dist'
New-Item -ItemType Directory -Path $dist -Force | Out-Null
$resource = Join-Path $dist ('omen-workspace-' + [guid]::NewGuid().ToString('N') + '.txt')
try {
    [IO.File]::WriteAllText($resource, $workspace, [Text.UTF8Encoding]::new($false))
    $target = Join-Path $dist 'RAVEN-X-Omen-Server.exe'
    $arguments = @('/nologo', '/target:winexe', '/platform:x64', '/optimize+',
        '/reference:System.Windows.Forms.dll', '/reference:System.Drawing.dll',
        "/out:$target", "/resource:$resource,workspace",
        ('/win32manifest:' + (Join-Path $PSScriptRoot 'OmenServerLauncher.manifest')),
        (Join-Path $PSScriptRoot 'OmenServerLauncher.cs'))
    & $compiler @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Omen Server launcher compilation failed.' }
    Get-Item -LiteralPath $target
} finally {
    Remove-Item -LiteralPath $resource -Force -ErrorAction SilentlyContinue
}
