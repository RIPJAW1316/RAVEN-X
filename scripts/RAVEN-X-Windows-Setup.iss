#ifndef ReleaseVersion
  #define ReleaseVersion "1.0.0"
#endif
#ifndef StageRoot
  #define StageRoot "..\dist\release\RAVEN-X-Agent-" + ReleaseVersion
#endif
#define MainScriptHash GetSHA256OfFile(StageRoot + "\scripts\install-agent.ps1")
#define WrapperScriptHash GetSHA256OfFile(StageRoot + "\scripts\setup-agent.ps1")
#define IntegrityScriptHash GetSHA256OfFile(StageRoot + "\scripts\release-integrity.ps1")
#define PayloadManifestHash GetSHA256OfFile(StageRoot + "\release-manifest.json")

[Setup]
AppId={{7B08A633-BE31-4490-950A-98C33071D740}
AppName=RAVEN-X Enterprise Endpoint Agent
AppVersion={#ReleaseVersion}
AppPublisher=NorthCypher Technologies
DefaultDirName={code:GetStageDir}
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousAppDir=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
#ifndef OutputBaseFilename
  #define OutputBaseFilename "RAVEN-X-Windows-Setup-v" + ReleaseVersion
#endif
OutputBaseFilename={#OutputBaseFilename}
Compression=lzma2
SolidCompression=yes
Uninstallable=no
CreateUninstallRegKey=no
WizardStyle=modern
SetupLogging=no
SetupMutex=Global\NorthCypher-RavenX-Endpoint-Setup
AppMutex=Global\NorthCypher-RavenX-Endpoint-Removal

[Files]
Source: "{#StageRoot}\*"; DestDir: "{app}\payload"; Flags: recursesubdirs createallsubdirs ignoreversion

[Dirs]
Name: "{app}\session"

[Code]
#include "setup-token-pipe.iss"

var
  TrustPage: TInputQueryWizardPage;
  CaPage: TInputFileWizardPage;
  TokenPage: TInputQueryWizardPage;
  SelectedStage: String;
  WorkerRunning: Boolean;

function GetStageDir(Param: String): String;
begin
  if SelectedStage = '' then SelectedStage := ExpandConstant('{commonpf64}\RavenXSetup\{#ReleaseVersion}-') + GetDateTimeString('yyyymmdd-hhnnss', '-', ':') + '-' + IntToStr(Random(1000000000));
  Result := SelectedStage;
end;

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
  TrustPage.Add('Enrollment ID (UUID):', False);
  TrustPage.Add('Independently verified public CA SHA-256:', False);
  CaPage := CreateInputFilePage(TrustPage.ID, 'Omen public CA',
    'Select the Omen public CA PEM',
    'Only the public CA certificate is accepted. Never select a private key.');
  CaPage.Add('Public CA PEM:', 'Certificate files|*.pem;*.crt|All files|*.*', '.pem');
  TokenPage := CreateInputQueryPage(CaPage.ID, 'Bootstrap token',
    'Enter the one-time token from Omen Enrollment',
    'Use the token issued with the enrollment ID entered on the connection page.');
  TokenPage.Add('Bootstrap token:', True);
end;

function ValidToken(Value: String): Boolean;
var I: Integer;
begin
  Result := Length(Value) = 43;
  if not Result then Exit;
  for I := 1 to Length(Value) do
    if Pos(Value[I], 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-') = 0 then
      begin Result := False; Exit; end;
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
      Exit;
    end;
    try
      if CompareText(GetSHA256OfFile(CaPage.Values[0]), TrustPage.Values[2]) <> 0 then begin
        MsgBox('The selected CA file does not match the fingerprint from the Omen. Check the CA file and the CA SHA-256 shown on the Omen server. The ZIP and Setup.exe hashes are separate values.', mbError, MB_OK);
        Result := False;
      end;
    except
      MsgBox('Setup could not read the selected CA file. Select a readable public CA PEM.', mbError, MB_OK);
      Result := False;
    end;
  end;
  if (CurPageID = TokenPage.ID) and not ValidToken(Trim(TokenPage.Values[0])) then begin
    MsgBox('Paste the complete bootstrap token from the Omen Enrollment dialog.', mbError, MB_OK);
    Result := False;
  end;
end;

function PsLiteral(Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '''', '''''', True);
end;

procedure CheckStageSecurity(Stage, Parent: String; Recursive: Boolean);
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
    'Check $pf;Check $parent;Check $stage;';
  if Recursive then Script := Script +
    '$todo=[Collections.Generic.Stack[string]]::new();$todo.Push($stage);' +
    'while($todo.Count -gt 0){$p=$todo.Pop();foreach($i in @(Get-ChildItem -LiteralPath $p -Force -ErrorAction Stop)){' +
    'Check $i.FullName;if($i.PSIsContainer){$todo.Push($i.FullName)}}}';
  Params := '-NoProfile -NonInteractive -Command "' + Script + '"';
  if not Exec(ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe'),
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


function InitializeSetup: Boolean;
begin
  Result := not WizardSilent and
    not DirExists(ExpandConstant('{commonpf64}\RavenX')) and
    not DirExists(ExpandConstant('{commonappdata}\RavenX'));
  if not Result then MsgBox('Interactive setup is required. If an earlier install failed, run Remove-RavenXClient.ps1 in Recovery mode. For an enrolled agent, use Uninstall only when you intend to remove it.', mbError, MB_OK);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var Parent: String;
begin
  Result := '';
  if CompareText(ExpandConstant('{app}'), GetStageDir('')) <> 0 then begin
    Result := 'The extraction path was overridden.'; Exit;
  end;
  if DirExists(ExpandConstant('{app}')) then begin
    Result := 'This attempt directory already exists.'; Exit;
  end;
  Parent := ExpandConstant('{commonpf64}\RavenXSetup');
  try
    if DirExists(Parent) then CheckStageSecurity(Parent, ExpandConstant('{commonpf64}'), False);
  except
    Result := 'Existing setup parent is not protected. No files were installed.';
  end;
end;

function JsonString(Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '"', '\"', True);
  StringChangeEx(Result, #13, '\r', True);
  StringChangeEx(Result, #10, '\n', True);
  StringChangeEx(Result, #9, '\t', True);
  Result := '"' + Result + '"';
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  if WorkerRunning then begin
    Cancel := False;
    Confirm := False;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Ica, Stage, Parent, Payload, Session, Params, PowerShell, Config, Failure, Token: String;
  OutputText: AnsiString;
  ExitCode: Integer;
  Started: Boolean;
begin
  if CurStep <> ssPostInstall then Exit;
  Stage := ExpandConstant('{app}');
  Parent := ExpandConstant('{commonpf64}\RavenXSetup');
  Payload := Stage + '\payload';
  Session := Stage + '\session';
  if CompareText(Stage, GetStageDir('')) <> 0 then
    RaiseException('Release extraction path changed.');
  Ica := ExpandConstant('{sysnative}\icacls.exe');
  PowerShell := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');
  RunChecked(Ica, AddQuotes(Parent) + ' /grant:r *S-1-5-18:F *S-1-5-32-544:F', 'Could not grant setup parent access.');
  RunChecked(Ica, AddQuotes(Parent) + ' /inheritance:r', 'Could not protect setup parent.');
  RunChecked(Ica, AddQuotes(Parent) + ' /setowner *S-1-5-32-544', 'Could not set setup parent owner.');
  RunChecked(Ica, AddQuotes(Stage) + ' /grant:r *S-1-5-18:F *S-1-5-32-544:F /T', 'Could not grant setup file access.');
  RunChecked(Ica, AddQuotes(Stage) + ' /inheritance:r /T', 'Could not protect setup files.');
  RunChecked(Ica, AddQuotes(Stage) + ' /setowner *S-1-5-32-544 /T', 'Could not set setup owners.');
  RunChecked(Ica, AddQuotes(Session) + ' /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F', 'Could not protect setup result directory.');
  CheckStageSecurity(Stage, Parent, True);
  if CompareText(GetSHA256OfFile(Payload + '\scripts\install-agent.ps1'), '{#MainScriptHash}') <> 0 then
    RaiseException('Installer script differs from the compiled release.');
  if CompareText(GetSHA256OfFile(Payload + '\scripts\release-integrity.ps1'), '{#IntegrityScriptHash}') <> 0 then
    RaiseException('Integrity verifier differs from the compiled release.');
  if CompareText(GetSHA256OfFile(Payload + '\scripts\setup-agent.ps1'), '{#WrapperScriptHash}') <> 0 then
    RaiseException('Setup wrapper differs from the compiled release.');
  Config := '{"server_url":' + JsonString(TrustPage.Values[0]) +
    ',"enrollment_id":' + JsonString(TrustPage.Values[1]) +
    ',"ca_path":' + JsonString(CaPage.Values[0]) +
    ',"ca_sha256":' + JsonString(TrustPage.Values[2]) + '}';
  if not SaveStringToFile(Session + '\connection.json', UTF8Encode(Config), False) then
    RaiseException('Could not save public connection settings.');
  RunChecked(Ica, AddQuotes(Session + '\connection.json') + ' /setowner *S-1-5-32-544', 'Could not set public settings owner.');
  CheckStageSecurity(Session, Parent, True);
  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + AddQuotes(Payload + '\scripts\setup-agent.ps1') +
    ' -ConfigPath ' + AddQuotes(Session + '\connection.json') +
    ' -ExpectedManifestSha256 {#PayloadManifestHash}';
  Token := Trim(TokenPage.Values[0]);
  TokenPage.Values[0] := '';
  WizardForm.StatusLabel.Caption := 'Verifying prerequisites and enrolling this computer. This can take several minutes.';
  WizardForm.CancelButton.Enabled := False;
  WorkerRunning := True;
  try
    Started := RunSetupWithToken(PowerShell, Params, Stage, Token, ExitCode);
  finally
    WorkerRunning := False;
  end;
  if not Started or (ExitCode <> 0) then begin
    Failure := 'Setup could not complete. For a partial install, run Remove-RavenXClient.ps1 in Recovery mode.';
    if LoadStringFromFile(Session + '\result.txt', OutputText) then Failure := UTF8Decode(OutputText);
    RaiseException(Failure + #13#10 + 'Diagnostic location: ' + Session);
  end;
  MsgBox('Agent installed and enrolled. Approve this computer in Omen Enrollment, then verify Online in Fleet and run an assessment.', mbInformation, MB_OK);
end;
