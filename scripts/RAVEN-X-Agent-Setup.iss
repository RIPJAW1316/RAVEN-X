#define ReleaseVersion "1.0.0-rc5"
#define StageRoot "..\dist\release\RAVEN-X-Agent-1.0.0-rc5"
#define MainScriptHash GetSHA256OfFile(StageRoot + "\scripts\install-agent.ps1")
#define IntegrityScriptHash GetSHA256OfFile(StageRoot + "\scripts\release-integrity.ps1")

[Setup]
AppId={{7B08A633-BE31-4490-950A-98C33071D740}
AppName=RAVEN-X Enterprise Endpoint Agent
AppVersion={#ReleaseVersion}
AppPublisher=NorthCypher Technologies
DefaultDirName={autopf}\RavenXRelease\{#ReleaseVersion}
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousAppDir=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=RAVEN-X-Agent-Setup-rc5
Compression=lzma2
SolidCompression=yes
Uninstallable=no
CreateUninstallRegKey=no
WizardStyle=modern
SetupLogging=no

[Files]
Source: "{#StageRoot}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Code]
var
  TrustPage: TInputQueryWizardPage;
  CaPage: TInputFileWizardPage;

function IsHex64(Value: String): Boolean;
var I: Integer;
begin
  Result := Length(Value) = 64;
  if not Result then Exit;
  for I := 1 to Length(Value) do
    if Pos(Value[I], '0123456789abcdefABCDEF') = 0 then begin Result := False; Exit; end;
end;

function IsUuid(Value: String): Boolean;
var I: Integer;
begin
  Result := Length(Value) = 36;
  if not Result then Exit;
  for I := 1 to 36 do begin
    if (I = 9) or (I = 14) or (I = 19) or (I = 24) then begin
      if Value[I] <> '-' then begin Result := False; Exit; end;
    end else if Pos(Value[I], '0123456789abcdefABCDEF') = 0 then begin Result := False; Exit; end;
  end;
end;

function SafeOriginCharacters(Value: String): Boolean;
var I: Integer;
begin
  Result := (Length(Value) >= 9) and (Length(Value) <= 2048) and
            (Copy(Value, 1, 8) = 'https://');
  if not Result then Exit;
  for I := 9 to Length(Value) do
    if Pos(Value[I], 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:/') = 0 then
      begin Result := False; Exit; end;
end;

procedure InitializeWizard;
begin
  TrustPage := CreateInputQueryPage(wpWelcome, 'Omen HTTPS connection',
    'Enter public connection details',
    'Get the CA SHA-256 fingerprint independently from the Omen administrator. Do not copy a fingerprint shipped with this Setup.exe.');
  TrustPage.Add('Omen HTTPS URL (for example https://192.168.1.121:8443):', False);
  TrustPage.Add('Fresh enrollment ID (UUID):', False);
  TrustPage.Add('Independently verified public CA SHA-256:', False);
  CaPage := CreateInputFilePage(TrustPage.ID, 'Omen public CA',
    'Select the Omen public CA PEM',
    'Only the public CA certificate is accepted. Never select a private key.');
  CaPage.Add('Public CA PEM:', 'Certificate files|*.pem;*.crt|All files|*.*', '.pem');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = TrustPage.ID then begin
    if not SafeOriginCharacters(TrustPage.Values[0]) or
       not IsUuid(TrustPage.Values[1]) or
       not IsHex64(TrustPage.Values[2]) then begin
      MsgBox('Enter a plain HTTPS origin, enrollment UUID and independent 64-character CA fingerprint.', mbError, MB_OK);
      Result := False;
    end;
  end;
  if CurPageID = CaPage.ID then begin
    if not FileExists(CaPage.Values[0]) then begin
      MsgBox('Select an existing public CA certificate file.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function InitializeSetup: Boolean;
begin
  Result := not WizardSilent and
            not DirExists(ExpandConstant('{autopf}\RavenXRelease')) and
            not DirExists(ExpandConstant('{autopf}\RavenX\Agent')) and
            not DirExists(ExpandConstant('{commonappdata}\RavenX\agent'));
  if not Result then
    MsgBox('Interactive setup is required, and no agent, credential directory or release stage may already exist. Preserve existing state and inspect recovery.', mbError, MB_OK);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if CompareText(ExpandConstant('{app}'), ExpandConstant('{autopf}\RavenXRelease\{#ReleaseVersion}')) <> 0 then
    Result := 'The release extraction path was overridden. Installation is refused.';
  if DirExists(ExpandConstant('{autopf}\RavenXRelease')) then
    Result := 'An existing release parent requires inspection before installation.';
end;

function PsLiteral(Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '''', '''''', True);
end;

procedure CheckStageSecurity(Stage, Parent: String);
var Script, Params: String; ExitCode: Integer;
begin
  { This code is embedded in the authenticated Setup.exe. It runs before any
    extracted script and rejects untrusted ACLs, owners and reparse points. }
  Script := '$ErrorActionPreference=''Stop'';' +
    '$trusted=@(''S-1-3-0'',''S-1-5-18'',''S-1-5-32-544'',''S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'');' +
    '$mask=0x10000000 -bor 0x40000000 -bor 0x00080000 -bor 0x00040000 -bor 0x00010000 -bor 0x00000002 -bor 0x00000004 -bor 0x00000010 -bor 0x00000100 -bor 0x00000040;' +
    'function Check($p){$i=Get-Item -LiteralPath $p -Force -ErrorAction Stop;' +
    'if(($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ''reparse''};' +
    '$a=Get-Acl -LiteralPath $p -ErrorAction Stop;' +
    'if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){throw ''owner''};' +
    'foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){' +
    'if($r.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ' +
    '$r.IdentityReference.Value -notin $trusted -and (([int]$r.FileSystemRights -band $mask) -ne 0)){throw ''writable''}}};' +
    '$pf=''' + PsLiteral(ExpandConstant('{autopf}')) + ''';' +
    '$parent=''' + PsLiteral(Parent) + ''';' +
    '$stage=''' + PsLiteral(Stage) + ''';' +
    'Check $pf;Check $parent;Check $stage;' +
    '$todo=[Collections.Generic.Stack[string]]::new();$todo.Push($stage);' +
    'while($todo.Count -gt 0){$p=$todo.Pop();foreach($i in @(Get-ChildItem -LiteralPath $p -Force -ErrorAction Stop)){' +
    'Check $i.FullName;if($i.PSIsContainer){$todo.Push($i.FullName)}}}';
  Params := '-NoProfile -NonInteractive -Command "' + Script + '"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      Params, Stage, SW_HIDE, ewWaitUntilTerminated, ExitCode) or (ExitCode <> 0) then
    RaiseException('Release staging security verification failed. No agent script was run.');
end;

procedure RunChecked(FileName, Parameters, MessageText: String);
var ExitCode: Integer;
begin
  ExitCode := -1;
  if not Exec(FileName, Parameters, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    RaiseException(MessageText + ' ACL tool could not start.');
  if ExitCode <> 0 then
    RaiseException(MessageText + ' ACL tool exit code: ' + IntToStr(ExitCode));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Ica, Stage, Parent, Params, PowerShell: String;
  ExitCode: Integer;
begin
  if CurStep <> ssPostInstall then Exit;
  Stage := ExpandConstant('{app}');
  Parent := ExpandConstant('{autopf}\RavenXRelease');
  if CompareText(Stage, ExpandConstant('{autopf}\RavenXRelease\{#ReleaseVersion}')) <> 0 then
    RaiseException('Release extraction path changed. No agent script was run.');
  Ica := ExpandConstant('{sys}\icacls.exe');
  PowerShell := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');

  { Program Files provides the initial protected extraction boundary. Lock the
    parent and every extracted child before any packaged script is executed. }
  { Grant explicit trusted access before removing inherited ACEs. Some Windows
    installations lose the only usable write-DAC path if inheritance goes first. }
  RunChecked(Ica, AddQuotes(Parent) + ' /grant:r *S-1-5-18:F *S-1-5-32-544:F', 'Could not set release parent ACL.');
  RunChecked(Ica, AddQuotes(Parent) + ' /inheritance:r', 'Could not protect release parent ACL.');
  RunChecked(Ica, AddQuotes(Parent) + ' /setowner *S-1-5-32-544', 'Could not set release parent owner.');
  RunChecked(Ica, AddQuotes(Stage) + ' /grant:r *S-1-5-18:F *S-1-5-32-544:F /T', 'Could not set release payload ACL.');
  RunChecked(Ica, AddQuotes(Stage) + ' /inheritance:r /T', 'Could not protect release payload ACL.');
  RunChecked(Ica, AddQuotes(Stage) + ' /setowner *S-1-5-32-544 /T', 'Could not set release payload owners.');

  CheckStageSecurity(Stage, Parent);
  if CompareText(GetSHA256OfFile(Stage + '\scripts\install-agent.ps1'), '{#MainScriptHash}') <> 0 then
    RaiseException('The extracted installer script differs from the compiled release.');
  if CompareText(GetSHA256OfFile(Stage + '\scripts\release-integrity.ps1'), '{#IntegrityScriptHash}') <> 0 then
    RaiseException('The extracted integrity verifier differs from the compiled release.');

  Params := '-NoProfile -ExecutionPolicy Bypass -File ' + AddQuotes(Stage + '\scripts\install-agent.ps1') +
    ' -ServerUrl ' + AddQuotes(TrustPage.Values[0]) +
    ' -EnrollmentId ' + AddQuotes(TrustPage.Values[1]) +
    ' -CaCertPath ' + AddQuotes(CaPage.Values[0]) +
    ' -CaCertSha256 ' + AddQuotes(TrustPage.Values[2]);
  if not Exec(PowerShell, Params, Stage, SW_SHOW, ewWaitUntilTerminated, ExitCode) or (ExitCode <> 0) then
    RaiseException('Agent installation did not complete. Preserve the partial state and follow BUILD_AND_INSTALL.md recovery guidance.');
  MsgBox('Agent enrolled and SYSTEM task registered. Approve this endpoint manually in the Omen portal.', mbInformation, MB_OK);
end;
