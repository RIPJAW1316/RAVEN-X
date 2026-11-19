{ The setup executable is x86. Native handle and pointer fields here are DWORDs. }
type
  TPipeSecurity = record
    Size, Descriptor, InheritHandle: LongWord;
  end;
  TChildStartup = record
    Size, Reserved, Desktop, Title, X, Y, XSize, YSize, XChars, YChars,
      Fill, Flags: LongWord;
    ShowWindow, ReservedSize: Word;
    Reserved2, StdIn, StdOut, StdErr: LongWord;
  end;
  TChildProcess = record
    ProcessHandle, ThreadHandle, ProcessId, ThreadId: LongWord;
  end;
  TSetupMessage = record
    Window, MessageId, WParam, LParam, Time, X, Y, PrivateData: LongWord;
  end;

function CreatePipe(var ReadEnd, WriteEnd: LongWord; var Security: TPipeSecurity;
  BufferSize: LongWord): Boolean;
  external 'CreatePipe@kernel32.dll stdcall';
function WritePipe(Handle: LongWord; Buffer: AnsiString; Count: LongWord;
  var Written: LongWord; Overlapped: LongWord): Boolean;
  external 'WriteFile@kernel32.dll stdcall';
function OpenConsoleSink(Name: String; Access, Share: LongWord;
  var Security: TPipeSecurity; Creation, Flags, Template: LongWord): LongWord;
  external 'CreateFileW@kernel32.dll stdcall';
function StartChild(ApplicationName, CommandLine: String; ProcessSecurity, ThreadSecurity: LongWord;
  InheritHandles: Boolean; Flags, Environment: LongWord; WorkDir: String;
  var Startup: TChildStartup; var Child: TChildProcess): Boolean;
  external 'CreateProcessW@kernel32.dll stdcall';
function CloseHandle(Handle: LongWord): Boolean;
  external 'CloseHandle@kernel32.dll stdcall';
function WaitForSingleObject(Handle, Timeout: LongWord): LongWord;
  external 'WaitForSingleObject@kernel32.dll stdcall';
function GetExitCodeProcess(Handle: LongWord; var ExitCode: Integer): Boolean;
  external 'GetExitCodeProcess@kernel32.dll stdcall';
function PeekSetupMessage(var Msg: TSetupMessage; Window, Min, Max, Remove: LongWord): Boolean;
  external 'PeekMessageW@user32.dll stdcall';
function TranslateSetupMessage(var Msg: TSetupMessage): Boolean;
  external 'TranslateMessage@user32.dll stdcall';
function DispatchSetupMessage(var Msg: TSetupMessage): LongInt;
  external 'DispatchMessageW@user32.dll stdcall';

function RunSetupWithToken(PowerShell, Params, WorkDir: String; var Token: String;
  var ExitCode: Integer): Boolean;
var
  Security: TPipeSecurity;
  Startup: TChildStartup;
  Child: TChildProcess;
  Msg: TSetupMessage;
  ReadEnd, WriteEnd, Sink, Written, WaitResult: LongWord;
  Wire: AnsiString;
begin
  Result := False;
  ExitCode := -1;
  Security.Size := 12;
  Security.Descriptor := 0;
  Security.InheritHandle := 1;
  Wire := AnsiString(Token + #10);
  Token := '';
  if not CreatePipe(ReadEnd, WriteEnd, Security, 4096) then Exit;
  try
    try
      if not WritePipe(WriteEnd, Wire, Length(Wire), Written, 0) or
        (Written <> Length(Wire)) then Exit;
    finally
      Wire := '';
      CloseHandle(WriteEnd);
    end;
    Sink := OpenConsoleSink('NUL', $40000000, 3, Security, 3, 0, 0);
    if Sink = $FFFFFFFF then Exit;
    try
      Startup.Size := 68;
      Startup.Flags := $100;
      Startup.StdIn := ReadEnd;
      Startup.StdOut := Sink;
      Startup.StdErr := Sink;
      if not StartChild(PowerShell, AddQuotes(PowerShell) + ' ' + Params, 0, 0, True,
        $08000000, 0, WorkDir, Startup, Child) then Exit;
    finally
      CloseHandle(Sink);
    end;
  finally
    CloseHandle(ReadEnd);
  end;
  CloseHandle(Child.ThreadHandle);
  try
    repeat
      WaitResult := WaitForSingleObject(Child.ProcessHandle, 50);
      { Keep the disabled install wizard painting and responding during setup. }
      while PeekSetupMessage(Msg, 0, 0, 0, 1) do begin
        TranslateSetupMessage(Msg);
        DispatchSetupMessage(Msg);
      end;
    until WaitResult <> 258;
    if WaitResult = 0 then Result := GetExitCodeProcess(Child.ProcessHandle, ExitCode);
  finally
    CloseHandle(Child.ProcessHandle);
  end;
end;
