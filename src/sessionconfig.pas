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

unit sessionconfig;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, IniFiles;

type
  TSwarmNode = record
    Host: string;
    Port: Integer;
    PubKey: string; { Hex X25519 Key }
  end;

  TContact = record
    Name: string;
    SessionID: string;
    Approved: Boolean;
  end;

  TSwarmNodeArray = array of TSwarmNode;
  TContactArray = array of TContact;

  TSessionConfig = class
  private
    FConfigPath: string;
    FDisplayName: string;
    FSeedHex: string;
    FSessionID: string;
    FSeedPath: string;
    FProfilePicURL: string;
    FProfilePicKey: string; { Hex }
    FPollInterval: Integer;
    FSwarmNodes: TSwarmNodeArray;
    FContacts: TContactArray;
    FUseTestnet: Boolean;
    procedure LoadDefaults;
    procedure LoadFromFile(const Path: string);
  public
    constructor Create;
    destructor Destroy; override;
    
    procedure Load(const AlternativePath: string = '');
    procedure Save;
    
    procedure AddContact(const Name, SessionID: string; Approved: Boolean = True);
    procedure RemoveContact(const Name: string);
    function FindContact(const Name: string): string;
    procedure AddSwarmNode(const Host: string; Port: Integer);
    procedure ClearSwarmNodes;
    
    property ConfigPath: string read FConfigPath write FConfigPath;
    property DisplayName: string read FDisplayName write FDisplayName;
    property SeedHex: string read FSeedHex write FSeedHex;
    property SessionID: string read FSessionID write FSessionID;
    property SeedPath: string read FSeedPath write FSeedPath;
    property ProfilePicURL: string read FProfilePicURL write FProfilePicURL;
    property ProfilePicKey: string read FProfilePicKey write FProfilePicKey;
    property PollInterval: Integer read FPollInterval write FPollInterval;
    property SwarmNodes: TSwarmNodeArray read FSwarmNodes;
    property Contacts: TContactArray read FContacts;
    property UseTestnet: Boolean read FUseTestnet write FUseTestnet;
  end;

var
  Config: TSessionConfig;

const
  DEFAULT_POLL_INTERVAL = 2000;
  DEFAULT_PORT = 22020; 
  CONFIG_FILENAME = 'session.conf';
  SEED_FILENAME = 'session_seed.bin';

implementation

constructor TSessionConfig.Create;
begin
  FConfigPath := ExpandFileName(CONFIG_FILENAME);
  LoadDefaults;
end;

destructor TSessionConfig.Destroy;
begin
  SetLength(FSwarmNodes, 0);
  SetLength(FContacts, 0);
  inherited Destroy;
end;

procedure TSessionConfig.LoadDefaults;
begin
  FDisplayName := '';
  FSeedHex := '';
  FSessionID := '';
  FSeedPath := GetAppConfigDir(False) + SEED_FILENAME;
  FProfilePicURL := '';
  FProfilePicKey := '';
  FPollInterval := DEFAULT_POLL_INTERVAL;
  FUseTestnet := False;
  
  { Load a list of known stable Foundation Nodes for redundancy }
  SetLength(FSwarmNodes, 3);
  
  { 1. Finland Node }
  FSwarmNodes[0].Host := '95.216.32.189'; 
  FSwarmNodes[0].Port := 22109;
  FSwarmNodes[0].PubKey := 'c8a2c5c333a9125eb83525ca90edd91afab38560755862784208b9497b0d6e3d';

  { 2. US Node }
  FSwarmNodes[1].Host := '185.150.191.47';
  FSwarmNodes[1].Port := 22138;
  FSwarmNodes[1].PubKey := '098203db37ab1c046a6a2c851c46f654dd81cf48bb53471e0944865951cd485f';

  { 3. Germany Node }
  FSwarmNodes[2].Host := '46.254.214.27';
  FSwarmNodes[2].Port := 22160;
  FSwarmNodes[2].PubKey := '6dc54d864e1d6972dc9b6c00f8656a3c65eb11224faa0c95171a26ddb7d4a35a';

  SetLength(FContacts, 0);
end;

procedure TSessionConfig.Load(const AlternativePath: string = '');
var
  ExePath, ExeDir: string;
begin
  if AlternativePath <> '' then
    FConfigPath := AlternativePath;

  // Try to find config file in multiple locations
  // 1. As absolute path or relative to current directory
  if FileExists(ExpandFileName(FConfigPath)) then
    FConfigPath := ExpandFileName(FConfigPath)
  // 2. In the executable's directory (for when running from bin/)
  else
  begin
    ExePath := ParamStr(0);
    ExeDir := ExtractFilePath(ExePath);
    if FileExists(ExeDir + FConfigPath) then
      FConfigPath := ExeDir + FConfigPath
    // 3. In parent of executable's directory (bin/ -> project root)
    else if FileExists(ExeDir + '../' + FConfigPath) then
      FConfigPath := ExeDir + '../' + FConfigPath
    // 4. In the src directory relative to exe
    else if FileExists(ExeDir + '../src/' + FConfigPath) then
      FConfigPath := ExeDir + '../src/' + FConfigPath;
  end;

  if FileExists(FConfigPath) then
    LoadFromFile(FConfigPath)
  else
    LoadDefaults;
end;

procedure TSessionConfig.LoadFromFile(const Path: string);
var
  IniFile: TIniFile;
  NodeCount, ContactCount, I: Integer;
  Section: string;
begin
  IniFile := TIniFile.Create(Path);
  try
    FDisplayName := IniFile.ReadString('Identity', 'DisplayName', '');
    FSeedHex := IniFile.ReadString('Identity', 'Seed', '');
    FSessionID := IniFile.ReadString('Identity', 'SessionID', '');
    FSeedPath := IniFile.ReadString('Paths', 'SeedFile', GetAppConfigDir(False) + SEED_FILENAME);
    FProfilePicURL := IniFile.ReadString('Identity', 'ProfilePicURL', '');
    FProfilePicKey := IniFile.ReadString('Identity', 'ProfilePicKey', '');
    FUseTestnet := IniFile.ReadInteger('Network', 'UseTestnet', 0) = 1;
    FPollInterval := IniFile.ReadInteger('Network', 'PollInterval', DEFAULT_POLL_INTERVAL);
    
    ContactCount := IniFile.ReadInteger('Contacts', 'Count', 0);
    if ContactCount > 0 then
    begin
      SetLength(FContacts, ContactCount);
      for I := 0 to ContactCount - 1 do
      begin
        Section := 'Contact' + IntToStr(I);
        FContacts[I].Name := IniFile.ReadString(Section, 'Name', '');
        FContacts[I].SessionID := IniFile.ReadString(Section, 'ID', '');
        FContacts[I].Approved := IniFile.ReadInteger(Section, 'Approved', 1) = 1;
      end;
    end;
    
    { Swarm nodes are currently hardcoded for stability, but we can load them if present }
    NodeCount := IniFile.ReadInteger('Swarm', 'NodeCount', 0);
    if NodeCount > 0 then
    begin
       SetLength(FSwarmNodes, NodeCount);
       for I := 0 to NodeCount - 1 do
       begin
         Section := 'Node' + IntToStr(I);
         FSwarmNodes[I].Host := IniFile.ReadString(Section, 'Host', '');
         FSwarmNodes[I].Port := IniFile.ReadInteger(Section, 'Port', DEFAULT_PORT);
         FSwarmNodes[I].PubKey := IniFile.ReadString(Section, 'PubKey', '');
       end;
    end;
    { Note: If no nodes found, we keep the defaults loaded in constructor/LoadDefaults }

  finally
    IniFile.Free;
  end;
end;

procedure TSessionConfig.Save;
var
  IniFile: TIniFile;
  I: Integer;
  Section: string;
  SeedHexToSave: string;
begin
  IniFile := TIniFile.Create(FConfigPath);
  try
    IniFile.WriteString('Identity', 'DisplayName', FDisplayName);
    // CRITICAL: Session uses 16-byte seeds (32 hex chars)
    // Always truncate to 32 chars when saving
    SeedHexToSave := Copy(FSeedHex, 1, 32);
    IniFile.WriteString('Identity', 'Seed', SeedHexToSave);
    IniFile.WriteString('Identity', 'SessionID', FSessionID);
    IniFile.WriteString('Paths', 'SeedFile', FSeedPath);
    IniFile.WriteString('Identity', 'ProfilePicURL', FProfilePicURL);
    IniFile.WriteString('Identity', 'ProfilePicKey', FProfilePicKey);
    if FUseTestnet then
      IniFile.WriteInteger('Network', 'UseTestnet', 1)
    else
      IniFile.WriteInteger('Network', 'UseTestnet', 0);
    
    IniFile.WriteInteger('Contacts', 'Count', Length(FContacts));
    for I := 0 to High(FContacts) do
    begin
      Section := 'Contact' + IntToStr(I);
      IniFile.WriteString(Section, 'Name', FContacts[I].Name);
      IniFile.WriteString(Section, 'ID', FContacts[I].SessionID);
      if FContacts[I].Approved then
        IniFile.WriteInteger(Section, 'Approved', 1)
      else
        IniFile.WriteInteger(Section, 'Approved', 0);
    end;

    IniFile.WriteInteger('Swarm', 'NodeCount', Length(FSwarmNodes));
    for I := 0 to High(FSwarmNodes) do
    begin
      Section := 'Node' + IntToStr(I);
      IniFile.WriteString(Section, 'Host', FSwarmNodes[I].Host);
      IniFile.WriteInteger(Section, 'Port', FSwarmNodes[I].Port);
      IniFile.WriteString(Section, 'PubKey', FSwarmNodes[I].PubKey);
    end;
  finally
    IniFile.Free;
  end;
end;

procedure TSessionConfig.AddContact(const Name, SessionID: string; Approved: Boolean = True);
begin
  SetLength(FContacts, Length(FContacts) + 1);
  FContacts[High(FContacts)].Name := Name;
  FContacts[High(FContacts)].SessionID := SessionID;
  FContacts[High(FContacts)].Approved := Approved;
  Save;
end;

procedure TSessionConfig.RemoveContact(const Name: string);
var
  I, J: Integer;
begin
  for I := 0 to High(FContacts) do
  begin
    if SameText(FContacts[I].Name, Name) then
    begin
      for J := I to High(FContacts) - 1 do
        FContacts[J] := FContacts[J + 1];
      SetLength(FContacts, Length(FContacts) - 1);
      Save;
      Break;
    end;
  end;
end;

function TSessionConfig.FindContact(const Name: string): string;
var
  I: Integer;
begin
  Result := '';
  { Check if Name is already a Session ID }
  if (Length(Name) = 66) and (Copy(Name, 1, 2) = '05') then
  begin
    Result := Name;
    Exit;
  end;

  for I := 0 to High(FContacts) do
  begin
    if SameText(FContacts[I].Name, Name) then
    begin
      Result := FContacts[I].SessionID;
      Break;
    end;
  end;
end;

procedure TSessionConfig.AddSwarmNode(const Host: string; Port: Integer);
begin
  SetLength(FSwarmNodes, Length(FSwarmNodes) + 1);
  FSwarmNodes[High(FSwarmNodes)].Host := Host;
  FSwarmNodes[High(FSwarmNodes)].Port := Port;
end;

procedure TSessionConfig.ClearSwarmNodes;
begin
  SetLength(FSwarmNodes, 0);
end;

initialization
  Config := TSessionConfig.Create;

finalization
  Config.Free;

end.
