; Package only the verified administrator ZIP in a fresh, protected directory.
#define ReleaseFolder "RAVEN-X-" + ReleaseVersion + "-" + Revision

[Setup]
AppName=RAVEN-X Omen Server
AppVersion={#ReleaseVersion}
AppPublisher=NorthCypher Technologies
DefaultDirName={commonpf64}\{#ReleaseFolder}
UsePreviousAppDir=no
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableWelcomePage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
Uninstallable=no
CreateUninstallRegKey=no
SetupMutex=Global\NorthCypher-RavenX-AdminSetup
CloseApplications=no
OutputBaseFilename=RAVEN-X-Omen-Setup
Compression=zip
WizardStyle=modern

[Files]
Source: "{#StageRoot}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{commonprograms}\RAVEN-X\Omen Server"; Filename: "{app}\RAVEN-X-Server.exe"; WorkingDir: "{app}"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  if CompareText(ExpandConstant('{app}'), ExpandConstant('{commonpf64}\{#ReleaseFolder}')) <> 0 then
    Result := 'Install this release in its protected Program Files directory.'
  else if DirExists(ExpandConstant('{app}')) or FileExists(ExpandConstant('{app}')) then
    Result := 'This build already has an installation directory. Open its RAVEN-X-Server.exe from Program Files.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep = ssPostInstall then
    if not Exec(ExpandConstant('{sys}\icacls.exe'), '"' + ExpandConstant('{app}') +
      '" /setowner *S-1-5-32-544 /T', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
      RaiseException('Windows could not apply the required administrator ownership to the installed release.');
end;
