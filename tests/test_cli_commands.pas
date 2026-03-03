{
  Session CLI
  Copyright (C) 2026 Eudox67

  Permission to use, copy, modify, and distribute this software and its
  associated documentation for any purpose and without fee is hereby granted,
  provided that the above copyright notice appears in all copies, and that
  both that copyright notice and this permission notice appear in supporting
  documentation, and that the name of the copyright holder not be used in
  advertising or publicity pertaining to distribution of the software without
  specific, written prior permission.

  THE COPYRIGHT HOLDER DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT
  SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY SPECIAL, INDIRECT OR
  CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM THE LOSS OF
  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
  OF THIS SOFTWARE.
}

unit test_cli_commands;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpcunit, testutils, testregistry, Process;

type
  TTestCLICommands = class(TTestCase)
  private
    function GetCLIPath: string;
  published
    procedure TestPollTimeout;
    procedure TestDaemonReady;
    procedure TestOnsResolveFormat;
  end;

implementation

function TTestCLICommands.GetCLIPath: string;
begin
  Result := ExtractFilePath(ParamStr(0)) + 'session-cli';
  if not FileExists(Result) then Result := ExtractFilePath(ParamStr(0)) + 'sessioncli';
  if not FileExists(Result) then Result := ExtractFilePath(ParamStr(0)) + '../src/session-cli';
  if not FileExists(Result) then
    Fail('session-cli binary not found. Please compile it first.');
end;

procedure TTestCLICommands.TestPollTimeout;
var
  AProcess: TProcess;
  OutputLines: TStringList;
  CLIPath: string;
  Buffer: array[0..2048] of byte;
  BytesRead: Integer;
  LoopCount: Integer;
begin
  CLIPath := GetCLIPath;
  AProcess := TProcess.Create(nil);
  OutputLines := TStringList.Create;
  try
    AProcess.Executable := CLIPath;
    AProcess.Parameters.Add('poll');
    AProcess.Parameters.Add('3'); 
    AProcess.Options := [poUsePipes]; 
    AProcess.CurrentDirectory := ExtractFilePath(CLIPath);
    AProcess.Execute;

    LoopCount := 0;
    while AProcess.Running do
    begin
      if AProcess.Output.NumBytesAvailable > 0 then
      begin
        BytesRead := AProcess.Output.Read(Buffer, SizeOf(Buffer));
        if BytesRead > 0 then
          OutputLines.Text := OutputLines.Text + Copy(String(PChar(@Buffer)), 1, BytesRead);
      end;
      Sleep(100);
      Inc(LoopCount);
      if LoopCount > 200 then 
      begin
        AProcess.Terminate(1);
        Fail('Test timed out waiting for sessioncli to exit');
      end;
    end;
    
    while AProcess.Output.NumBytesAvailable > 0 do
    begin
        BytesRead := AProcess.Output.Read(Buffer, SizeOf(Buffer));
        if BytesRead > 0 then
          OutputLines.Text := OutputLines.Text + Copy(String(PChar(@Buffer)), 1, BytesRead);
    end;

    AssertEquals('CLI should exit with code 0', 0, AProcess.ExitCode);
    AssertTrue('Output should contain polling start message', Pos('Polling for messages', OutputLines.Text) > 0);
  finally
    AProcess.Free;
    OutputLines.Free;
  end;
end;

procedure TTestCLICommands.TestDaemonReady;
var
  AProcess: TProcess;
  OutputLines: TStringList;
  CLIPath, Line: string;
  Buffer: array[0..2048] of byte;
  BytesRead: Integer;
  LoopCount: Integer;
begin
  CLIPath := GetCLIPath;
  AProcess := TProcess.Create(nil);
  OutputLines := TStringList.Create;
  try
    AProcess.Executable := CLIPath;
    AProcess.Parameters.Add('daemon');
    AProcess.Options := [poUsePipes];
    AProcess.CurrentDirectory := ExtractFilePath(CLIPath);
    AProcess.Execute;

    LoopCount := 0;
    while (LoopCount < 100) do
    begin
      if AProcess.Output.NumBytesAvailable > 0 then
      begin
        BytesRead := AProcess.Output.Read(Buffer, SizeOf(Buffer));
        if BytesRead > 0 then
          OutputLines.Text := OutputLines.Text + Copy(String(PChar(@Buffer)), 1, BytesRead);
      end;
      
      if AProcess.Stderr.NumBytesAvailable > 0 then
      begin
        BytesRead := AProcess.Stderr.Read(Buffer, SizeOf(Buffer));
        if BytesRead > 0 then
          OutputLines.Text := OutputLines.Text + ' ERR: ' + Copy(String(PChar(@Buffer)), 1, BytesRead);
      end;

      if Pos('"method":"ready"', OutputLines.Text) > 0 then Break;
      if not AProcess.Running then Break;
      
      Sleep(100);
      Inc(LoopCount);
    end;

    AssertTrue('Daemon should output ready JSON. Got: "' + OutputLines.Text + '" (ExitCode: ' + IntToStr(AProcess.ExitCode) + ')', Pos('"method":"ready"', OutputLines.Text) > 0);
    
    { Send quit }
    Line := '{"method":"quit"}' + sLineBreak;
    AProcess.Input.Write(PChar(Line)^, Length(Line));
    Sleep(200); // Wait for daemon to receive
    
    LoopCount := 0;
    while (LoopCount < 100) and AProcess.Running do
    begin
      Sleep(100);
      Inc(LoopCount);
    end;
    
    AssertTrue('Daemon should exit after quit. (ExitCode: ' + IntToStr(AProcess.ExitCode) + ')', not AProcess.Running);
  finally
    if AProcess.Running then AProcess.Terminate(0);
    AProcess.Free;
    OutputLines.Free;
  end;
end;

procedure TTestCLICommands.TestOnsResolveFormat;
var
  AProcess: TProcess;
  OutputLines: TStringList;
  CLIPath: string;
  Buffer: array[0..2048] of byte;
  BytesRead: Integer;
begin
  CLIPath := GetCLIPath;
  AProcess := TProcess.Create(nil);
  OutputLines := TStringList.Create;
  try
    AProcess.Executable := CLIPath;
    AProcess.Parameters.Add('ons');
    AProcess.Parameters.Add('resolve');
    AProcess.Parameters.Add('nosuchuser12345');
    AProcess.Options := [poUsePipes];
    AProcess.CurrentDirectory := ExtractFilePath(CLIPath);
    AProcess.Execute;

    while AProcess.Running do
    begin
      if AProcess.Output.NumBytesAvailable > 0 then
      begin
        BytesRead := AProcess.Output.Read(Buffer, SizeOf(Buffer));
        OutputLines.Text := OutputLines.Text + Copy(String(PChar(@Buffer)), 1, BytesRead);
      end;
      Sleep(100);
    end;

    AssertTrue('Should print resolving message. Got: ' + OutputLines.Text, Pos('Resolving nosuchuser12345', OutputLines.Text) > 0);
  finally
    AProcess.Free;
    OutputLines.Free;
  end;
end;

initialization
  RegisterTest(TTestCLICommands);
end.
