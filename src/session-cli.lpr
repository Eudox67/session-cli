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

program session_cli;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils, DateUtils, fpjson, opensslsockets,
  sessionconfig, sessionclient, sessioncrypto, sessionnetwork, libsession, sessionmnemonic;

const
  VERSION = '0.2.0 (LibSession)';

var
  Cmd: string;
  Client: TSessionClient;
  Verbose: Boolean = False;
  ArgIdx: Integer = 1;

procedure ShowHelp;
begin
  WriteLn('PrivateScout CLI - Session Protocol Client');
  WriteLn('Version: ', VERSION);
  WriteLn;
  WriteLn('Usage: session-cli [options] <command> [arguments]');
  WriteLn;
  WriteLn('Options:');
  WriteLn('  -v, --verbose         Enable detailed debug output');
  WriteLn('  --config <path>       Specify an alternative configuration file');
  WriteLn;
  WriteLn('Core Commands:');
  WriteLn('  init [--force]        Generate a new Session Identity');
  WriteLn('  info                  Show your Session ID and status');
  WriteLn('  mnemonic              Show recovery phrase');
  WriteLn;
  WriteLn('Messaging:');
  WriteLn('  send <ID> <MSG> [FILE] Send an encrypted message (with optional file)');
  WriteLn('  send-file <ID> <PATH> Send a file attachment');
  WriteLn('  download <URL> <KEY> <PATH> Download and decrypt an attachment');
  WriteLn('  delete <HASH> [...]   Delete messages from swarm by hash');
  WriteLn('  request list          List pending message requests');
  WriteLn('  request accept <ID> [N] Accept a request');
  WriteLn('  poll [timeout]        Check for new messages (Loop)');
  WriteLn('  receive               Check for messages once and output JSON');
  WriteLn('  listen [timeout]      Continuous poll with JSON output');
  WriteLn('  daemon                Persistent JSON-RPC interface (for OpenClaw)');
  WriteLn;
  WriteLn('Profile:');
  WriteLn('  profile get           Show your current display name');
  WriteLn('  profile set <NAME>    Set your Display Name');
  WriteLn('  profile set-picture <PATH> Set your Profile Picture');
  WriteLn('  profile clean         Delete all old profile messages from namespace 2');
  WriteLn('  sync pull             Pull profile/contacts from cloud');
  WriteLn('  sync push             Push local profile/contacts to cloud');
  WriteLn;
  WriteLn('Contacts:');
  WriteLn('  contact list          List saved contacts');
  WriteLn('  contact add <N> <ID>  Add a new contact');
  WriteLn('  contact rm <N>        Remove a contact');
  WriteLn;
  WriteLn('Network:');
  WriteLn('  ons resolve <NAME>    Resolve an ONS name to a Session ID');
  WriteLn('  get-swarm <ID>        Lookup swarm nodes for a Session ID');
  WriteLn;
end;

procedure DoSync;
var
  Sub: string;
  ParamOffset: Integer;
begin
  ParamOffset := ArgIdx - 1;
  if ParamCount < 2 + ParamOffset then
  begin
    WriteLn('Usage: session-cli sync <pull|push>');
    Exit;
  end;
  Sub := LowerCase(ParamStr(2 + ParamOffset));
  Client.EnsureIdentity;
  if Sub = 'pull' then Client.PullSyncData
  else if Sub = 'push' then Client.Sync
  else WriteLn('Unknown sync command: ', Sub);
end;

procedure DoRequest;
var
  Sub, ID, Name: string;
  Reqs: TJSONArray;
  i: integer;
  ParamOffset: Integer;
begin
  ParamOffset := ArgIdx - 1;
  if ParamCount < 2 + ParamOffset then
  begin
    WriteLn('Usage: session-cli request <list|accept>');
    Exit;
  end;
  Sub := LowerCase(ParamStr(2 + ParamOffset));
  Client.EnsureIdentity;
  if Sub = 'list' then
  begin
    Reqs := Client.RequestList;
    try
      if Reqs.Count = 0 then WriteLn('No pending requests.')
      else
      begin
        WriteLn('Pending Requests:');
        for i := 0 to Reqs.Count - 1 do
          WriteLn(Format('  %s: %s', [Reqs.Objects[i].Strings['sender'], Reqs.Objects[i].Strings['message']]));
      end;
    finally Reqs.Free; end;
  end
  else if Sub = 'accept' then
  begin
    if ParamCount < 3 + ParamOffset then WriteLn('Usage: session-cli request accept <SessionID> [Nickname]')
    else
    begin
      ID := ParamStr(3 + ParamOffset);
      if ParamCount >= 4 + ParamOffset then Name := ParamStr(4 + ParamOffset) else Name := '';
      Client.AcceptRequest(ID, Name);
    end;
  end;
end;

procedure DoContacts;
var
  Sub: string;
  I: Integer;
  ParamOffset: Integer;
begin
  ParamOffset := ArgIdx - 1;
  if ParamCount < 2 + ParamOffset then
  begin
    WriteLn('Usage: session-cli contact <list|add|rm>');
    Exit;
  end;

  Sub := LowerCase(ParamStr(2 + ParamOffset));
  if Sub = 'list' then
  begin
    WriteLn('Contacts:');
    for I := 0 to High(Client.Config.Contacts) do
      WriteLn(Format('  %-20s %s', [Client.Config.Contacts[I].Name, Client.Config.Contacts[I].SessionID]));
  end
  else if Sub = 'add' then
  begin
    if ParamCount < 4 + ParamOffset then
      WriteLn('Usage: session-cli contact add <Name> <SessionID>')
    else
    begin
      Client.AddContact(ParamStr(3 + ParamOffset), ParamStr(4 + ParamOffset));
      WriteLn('Contact added.');
    end;
  end
  else if Sub = 'rm' then
  begin
    if ParamCount < 3 + ParamOffset then
      WriteLn('Usage: session-cli contact rm <Name>')
    else
    begin
      Client.RemoveContact(ParamStr(3 + ParamOffset));
      WriteLn('Contact removed.');
    end;
  end;
end;

procedure DoReceive;
begin
  Client.EnsureIdentity;
  Client.OutputFormat := ofJSON;
  Client.PollMessages;
end;

procedure DoMnemonic;
var
  Mnemonic: string;
  SeedUsed, RecoveredSeed: string;
begin
  Client.EnsureIdentity;

  SeedUsed := Copy(Client.Config.SeedHex, 1, 32);
  if Verbose then
  begin
    WriteLn(StdErr, 'DEBUG: Full seed (64 hex): ', Client.Config.SeedHex);
    WriteLn(StdErr, 'DEBUG: First 16 bytes used: ', SeedUsed);
  end;

  Mnemonic := SeedToMnemonic(SeedUsed);
  WriteLn('Recovery Phrase (13 words):');
  WriteLn;
  WriteLn(Mnemonic);
  WriteLn;
  WriteLn('WARNING: Save these words securely! They can be used to recover your identity.');
end;

procedure DoInit;
var
  Force: Boolean;
  I: Integer;
begin
  Force := False;
  for I := 1 to ParamCount do
    if SameText(ParamStr(I), '--force') then
    begin
      Force := True;
      Break;
    end;
  
  if Force then
  begin
    WriteLn('Forcing generation of a NEW identity...');
    Client.Config.SeedHex := '';
    if FileExists(Client.Config.SeedPath) then
    begin
      WriteLn('Deleting existing seed file: ', Client.Config.SeedPath);
      DeleteFile(Client.Config.SeedPath);
    end;
    Client.Config.DisplayName := '';
    Client.Config.Save;
  end;

  Client.EnsureIdentity;
  WriteLn('Success!');
  WriteLn('Session ID: ', Client.Config.SessionID);
end;

procedure DoInfo;
begin
  Client.EnsureIdentity;
  WriteLn('Session ID: ', Client.Config.SessionID);
  WriteLn('Display Name: ', Client.Config.DisplayName);
  WriteLn('Bootstrap Node: ', Client.Config.SwarmNodes[0].Host);
end;

procedure DoSend;
var
  Dest, Msg, Atch, Line: string;
  ParamOffset: Integer;
begin
  // Account for -v flag
  ParamOffset := ArgIdx - 1;

  if ParamCount < 3 + ParamOffset then
  begin
    WriteLn('Usage: session-cli send <SessionID> <Message | -> [AttachmentPath]');
    Exit;
  end;

  Dest := ParamStr(2 + ParamOffset);
  Msg := ParamStr(3 + ParamOffset);
  Atch := '';
  if ParamCount >= 4 + ParamOffset then
    Atch := ParamStr(4 + ParamOffset);

  if Msg = '-' then
  begin
    Msg := '';
    while not EOF(Input) do
    begin
      ReadLn(Input, Line);
      Msg := Msg + Line + sLineBreak;
    end;
  end;

  Client.EnsureIdentity;
  if Verbose then WriteLn('Sending from: ', Client.Config.SessionID);
  if not Client.SendMessage(Dest, Msg, Atch) then ExitCode := 1;
end;
procedure DoSendFile;
var
  Dest, Path: string;
  ParamOffset: Integer;
begin
  ParamOffset := ArgIdx - 1;
  if ParamCount < 3 + ParamOffset then
  begin
    WriteLn('Usage: session-cli send-file <SessionID> <FilePath>');
    Exit;
  end;
  Dest := ParamStr(2 + ParamOffset);
  Path := ParamStr(3 + ParamOffset);
  Client.EnsureIdentity;
  if not Client.SendFile(Dest, Path) then ExitCode := 1;
end;

procedure DoDownload;
var
  URL, Key, Path: string;
  ParamOffset: Integer;
begin
  ParamOffset := ArgIdx - 1;
  if ParamCount < 4 + ParamOffset then
  begin
    WriteLn('Usage: session-cli download <URL> <KeyHex> <SavePath>');
    Exit;
  end;
  URL := ParamStr(2 + ParamOffset);
  Key := ParamStr(3 + ParamOffset);
  Path := ParamStr(4 + ParamOffset);
  if not Client.DownloadFile(URL, Key, Path) then ExitCode := 1;
end;

procedure DoDelete;
var
  Hashes: array of string;
  i, StartIdx: Integer;
begin
  StartIdx := ArgIdx + 1;

  if ParamCount < StartIdx then
  begin
    WriteLn('Usage: session-cli delete <Hash1> [Hash2] ...');
    Exit;
  end;

  SetLength(Hashes, ParamCount - StartIdx + 1);
  for i := 0 to High(Hashes) do
    Hashes[i] := ParamStr(StartIdx + i);

  Client.EnsureIdentity;
  Client.DeleteMessages(Hashes);
end;

procedure DoProfile;
var
  Sub: string;
  ParamOffset: Integer;
begin
  // Account for -v flag
  ParamOffset := ArgIdx - 1;
  
  if ParamCount < 2 + ParamOffset then
  begin
    WriteLn('Usage: session-cli profile <get|set|set-picture|clean>');
    Exit;
  end;

  Sub := LowerCase(ParamStr(2 + ParamOffset));
  if Sub = 'get' then
  begin
    Client.EnsureIdentity;
    WriteLn('Display Name: ', Client.Config.DisplayName);
    if Client.Config.ProfilePicURL <> '' then
      WriteLn('Profile Pic URL: ', Client.Config.ProfilePicURL);
  end
  else if Sub = 'set' then
  begin
    if ParamCount < 3 + ParamOffset then
      WriteLn('Usage: session-cli profile set <Name>')
    else
    begin
      Client.EnsureIdentity;
      Client.SetDisplayName(ParamStr(3 + ParamOffset));
      Client.Sync;
    end;
  end
  else if Sub = 'set-picture' then
  begin
    if ParamCount < 3 + ParamOffset then
      WriteLn('Usage: session-cli profile set-picture <FilePath>')
    else
    begin
      Client.SetProfilePicture(ParamStr(3 + ParamOffset));
    end;
  end
  else if Sub = 'clean' then
  begin
    Client.EnsureIdentity;
    WriteLn('Cleaning old profile messages from namespace 2...');
    if Client.CleanProfileNamespace then
      WriteLn('Profile namespace cleaned successfully.')
    else
    begin
      WriteLn('Failed to clean profile namespace.');
      ExitCode := 1;
    end;
  end;
end;

procedure DoGetSwarm;
var
  Target: string;
  ParamOffset: Integer;
begin
  ParamOffset := ArgIdx - 1;
  if ParamCount < 2 + ParamOffset then
  begin
    WriteLn('Usage: session-cli get-swarm <SessionID>');
    Exit;
  end;

  Target := ParamStr(2 + ParamOffset);
  Client.EnsureIdentity;

  WriteLn('Querying swarm for ', Target, '...');
  if Client.Network.GetSwarm(Target) then
  begin
    WriteLn('Successfully retrieved swarm info');
    Client.Config.Save;
  end
  else
  begin
    WriteLn('Failed to retrieve swarm.');
    ExitCode := 1;
  end;
end;

procedure DoPoll;
var
  Timeout, PollParamIdx: Integer;
  StartTime: TDateTime;
begin
  Timeout := 0;
  PollParamIdx := ArgIdx + 1;

  if ParamCount >= PollParamIdx then
    Timeout := StrToIntDef(ParamStr(PollParamIdx), 0);

  Client.EnsureIdentity;
  if Timeout > 0 then
    WriteLn(Format('Polling for messages (Timeout: %d sec)...', [Timeout]))
  else
    WriteLn('Polling for messages (Ctrl+C to stop)...');

  StartTime := Now;

  while True do
  begin
    Client.PollMessages;
    if (Timeout > 0) and (SecondsBetween(Now, StartTime) >= Timeout) then Break;
    Sleep(Client.Config.PollInterval);
  end;
end;

procedure DoListen;
var
  Timeout, ListenParamIdx: Integer;
  StartTime: TDateTime;
begin
  Timeout := 0;
  ListenParamIdx := ArgIdx + 1;

  if ParamCount >= ListenParamIdx then
    Timeout := StrToIntDef(ParamStr(ListenParamIdx), 0);

  Client.EnsureIdentity;
  Client.OutputFormat := ofJSON;

  StartTime := Now;

  while True do
  begin
    Client.PollMessages;
    if (Timeout > 0) and (SecondsBetween(Now, StartTime) >= Timeout) then Break;
    Sleep(Client.Config.PollInterval);
  end;
end;

procedure DoOns;
var
  Sub, Name, Resolved: string;
  ParamOffset: Integer;
begin
  ParamOffset := ArgIdx - 1;
  if ParamCount < 3 + ParamOffset then
  begin
    WriteLn('Usage: session-cli ons resolve <Name>');
    Exit;
  end;

  Sub := LowerCase(ParamStr(2 + ParamOffset));
  if Sub = 'resolve' then
  begin
    Name := ParamStr(3 + ParamOffset);
    WriteLn('Resolving ', Name, '...');
    Resolved := Client.ResolveONS(Name);
    if Resolved <> '' then
      WriteLn('Resolved Session ID: ', Resolved)
    else
      WriteLn('Failed to resolve ONS name.');
  end;
end;

type
  TPollThread = class(TThread)
  private
    FClient: TSessionClient;
  protected
    procedure Execute; override;
  public
    constructor Create(AClient: TSessionClient);
  end;

constructor TPollThread.Create(AClient: TSessionClient);
begin
  inherited Create(False);
  FClient := AClient;
  FreeOnTerminate := False;
end;

procedure TPollThread.Execute;
begin
  while not Terminated do
  begin
    try
      FClient.PollMessages;
    except
    end;
    Sleep(FClient.Config.PollInterval);
  end;
end;

procedure DoDaemon;
var
  Line: string;
  JsonMsg: TJSONData;
  Method: string;
  Params: TJSONObject;
  PollThread: TPollThread;
begin
  Client.EnsureIdentity;
  Client.OutputFormat := ofJSON;

  PollThread := TPollThread.Create(Client);
  try
    WriteLn('{"jsonrpc":"2.0","method":"ready"}');
    Flush(Output);

    while not EOF(Input) do
    begin
      ReadLn(Input, Line);
      if Line = '' then Continue;

      try
        JsonMsg := GetJSON(Line);
        try
          if (JsonMsg.JSONType = jtObject) then
          begin
            Method := TJSONObject(JsonMsg).Strings['method'];
            if TJSONObject(JsonMsg).Find('params') <> nil then
              Params := TJSONObject(JsonMsg).Find('params') as TJSONObject
            else
              Params := nil;

            if Method = 'send' then
            begin
              if (Params <> nil) then
                Client.SendMessage(Params.Strings['recipient'], Params.Strings['message']);
            end
            else if Method = 'sync' then
            begin
              Client.Sync;
            end
            else if Method = 'quit' then
            begin
              Break;
            end;
          end;
        finally
          JsonMsg.Free;
        end;
      except
        on E: Exception do
          WriteLn('{"jsonrpc":"2.0","error":{"code":-32603,"message":"' + E.Message + '"}}');
      end;
      Flush(Output);
    end;
  finally
    PollThread.Terminate;
    PollThread.WaitFor;
    PollThread.Free;
  end;
end;

var
  ConfigPath: string = '';
begin
  if ParamCount = 0 then
  begin
    ShowHelp;
    Exit;
  end;

  ArgIdx := 1;
  while (ArgIdx <= ParamCount) and (ParamStr(ArgIdx)[1] = '-') do
  begin
    if (ParamStr(ArgIdx) = '-v') or (ParamStr(ArgIdx) = '--verbose') then
    begin
      Verbose := True;
      Inc(ArgIdx);
    end
    else if (ParamStr(ArgIdx) = '--config') and (ArgIdx < ParamCount) then
    begin
      ConfigPath := ParamStr(ArgIdx + 1);
      Inc(ArgIdx, 2);
    end
    else
      Break;
  end;

  if ParamCount < ArgIdx then
  begin
    ShowHelp;
    Exit;
  end;

  try
    Config.Load(ConfigPath);
    Client := TSessionClient.Create(Config);
    try
      Client.Verbose := Verbose;
      Cmd := LowerCase(ParamStr(ArgIdx));

      if Cmd = 'init' then DoInit
      else if Cmd = 'info' then DoInfo
      else if Cmd = 'mnemonic' then DoMnemonic
      else if Cmd = 'send' then DoSend
      else if Cmd = 'send-file' then DoSendFile
      else if Cmd = 'download' then DoDownload
      else if Cmd = 'sync' then DoSync
      else if Cmd = 'request' then DoRequest
      else if Cmd = 'delete' then DoDelete
      else if Cmd = 'profile' then DoProfile
      else if Cmd = 'get-swarm' then DoGetSwarm
      else if Cmd = 'poll' then DoPoll
      else if Cmd = 'listen' then DoListen
      else if Cmd = 'daemon' then DoDaemon
      else if Cmd = 'receive' then DoReceive
      else if Cmd = 'contact' then DoContacts
      else if Cmd = 'ons' then DoOns
      else ShowHelp;
    finally
      Client.Free;
    end;
  except
    on E: Exception do
    begin
      WriteLn('Fatal Error: ', E.ClassName, ': ', E.Message);
      if (ExceptAddr <> nil) then
        WriteLn('At address: ', HexStr(ExceptAddr));
      ExitCode := 1;
    end;
  end;
end.
