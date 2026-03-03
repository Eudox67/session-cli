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

unit sessionclient;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, DateUtils, sessioncrypto, sessionconfig, sessionnetwork, fpjson, libsession, base64, strutils, zmq_utils;

type
  TOutputFormat = (ofText, ofJSON);

  TSessionClient = class
  private
    FConfig: TSessionConfig;
    FIdentity: TSessionIdentity;
    FNetwork: TSessionNetwork;
    FVerbose: Boolean;
    FLastMessageHash: string;
    FOutputFormat: TOutputFormat;
    FMsgCounter: Integer; // Added for JSON commas
    procedure ProcessMessageList(msgs: TJSONArray);
  public
    constructor Create(AConfig: TSessionConfig);
    destructor Destroy; override;
    
    procedure EnsureIdentity;
    function SendMessage(const recipientID, text: string; const attachmentFilePath: string = ''): Boolean;
    function SendFile(const recipientID, filePath: string): Boolean;
    function DownloadFile(const URL: string; const KeyHex: string; const savePath: string): Boolean;
    procedure PollMessages;
    procedure DeleteMessages(const Hashes: array of string);
    procedure SetDisplayName(const NewName: string);
    procedure SetProfilePicture(const FilePath: string);
    procedure Sync;
    procedure PullSyncData;
    
    function RequestList: TJSONArray;
    procedure AcceptRequest(const sessionID: string; const name: string = '');
    function ResolveONS(const Name: string): string;
    function CleanProfileNamespace: Boolean;
    procedure AddContact(const name, sessionID: string);
    procedure RemoveContact(const name: string);
    procedure ListContacts;

    property Config: TSessionConfig read FConfig;
    property Verbose: Boolean read FVerbose write FVerbose;
    property OutputFormat: TOutputFormat read FOutputFormat write FOutputFormat;
    property Network: TSessionNetwork read FNetwork;
  end;

implementation

constructor TSessionClient.Create(AConfig: TSessionConfig);
begin
  FConfig := AConfig;
  FNetwork := TSessionNetwork.Create(FConfig);
  FOutputFormat := ofText;
end;

destructor TSessionClient.Destroy;
begin
  FNetwork.Free;
  inherited Destroy;
end;

procedure TSessionClient.EnsureIdentity;
begin
  if not LoadIdentity(FConfig.SeedPath, FIdentity) then
  begin
    writeln('No identity found at ', FConfig.SeedPath, '. Generating new identity...');
    GenerateNewIdentity(FIdentity);
    if not SaveIdentity(FConfig.SeedPath, FIdentity) then
      raise Exception.Create('Failed to save new identity');
    FConfig.SeedHex := sessioncrypto.BytesToHex(@FIdentity.Seed[0], 32);
    FConfig.SessionID := FIdentity.SessionID;
    FConfig.Save;
    writeln('New identity generated: ', FIdentity.SessionID);
  end
  else
  begin
    FConfig.SeedHex := sessioncrypto.BytesToHex(@FIdentity.Seed[0], 32);
    FConfig.SessionID := FIdentity.SessionID;
  end;
end;

function TSessionClient.SendMessage(const recipientID, text: string; const attachmentFilePath: string = ''): Boolean;
var
  resolvedID: string;
  EncryptedData: string;
  Atch: TAttachment;
  AtchURL, AtchDigest: string;
  AtchKey: TBytes;
  AtchArray: TAttachmentArray;
  FSize: int64;
begin
  Result := False;
  EnsureIdentity;
  resolvedID := FConfig.FindContact(recipientID);
  if resolvedID = '' then resolvedID := recipientID;
  
  if FVerbose then writeln(StdErr, 'DEBUG: SendMessage - resolvedID: ', resolvedID);
  
  AtchArray := nil;
  if (attachmentFilePath <> '') and FileExists(attachmentFilePath) then
  begin
    if FVerbose then writeln(StdErr, 'DEBUG: SendMessage - uploading attachment: ', attachmentFilePath);
    if FNetwork.UploadFile(attachmentFilePath, FIdentity, AtchURL, AtchKey, AtchDigest, False) then
    begin
      if FVerbose then writeln(StdErr, 'DEBUG: SendMessage - upload successful');
      Atch.URL := AtchURL;
      Atch.Key := AtchKey;
      Atch.FileName := ExtractFileName(attachmentFilePath);
      
      FSize := 0;
      with TFileStream.Create(attachmentFilePath, fmOpenRead or fmShareDenyNone) do
      try FSize := Size; finally Free; end;
      Atch.Size := FSize;
      
      SetLength(Atch.Digest, 32);
      sessioncrypto.HexToBytes(AtchDigest, @Atch.Digest[0]);
      SetLength(AtchArray, 1);
      AtchArray[0] := Atch;
      if FVerbose then writeln(StdErr, 'DEBUG: SendMessage - attachment URL: ', AtchURL);
    end
    else
    begin
      writeln('Warning: Failed to upload attachment. Sending message without it.');
    end;
  end;

  try
    if FVerbose then writeln(StdErr, 'DEBUG: SendMessage - calling EncryptMessage...');
    EncryptedData := sessioncrypto.EncryptMessage(text, resolvedID, FIdentity, FConfig.DisplayName, FConfig.ProfilePicURL, FConfig.ProfilePicKey, AtchArray);
    if FVerbose then writeln(StdErr, 'DEBUG: SendMessage - EncryptMessage returned, length: ', Length(EncryptedData));
  except
    on E: Exception do
    begin
      writeln('Encryption Error: ', E.Message);
      Exit;
    end;
  end;

  if Length(EncryptedData) = 0 then
  begin
    writeln('Failed to encrypt message.');
    Exit;
  end;

  if FVerbose then writeln(StdErr, 'DEBUG: SendMessage - ciphertext base64: ', EncodeStringBase64(EncryptedData));
  if FVerbose then writeln(StdErr, 'DEBUG: SendMessage - calling StoreMessage...');
  FNetwork.Verbose := FVerbose;  // Ensure network has verbose flag
  if FNetwork.StoreMessage(resolvedID, EncryptedData, FIdentity.Ed25519SK) then
    begin
       if FOutputFormat = ofText then
         writeln('Message sent to ', resolvedID);
       Result := True;
    end
  else
    writeln('Failed to send message.');
end;

function TSessionClient.SendFile(const recipientID, filePath: string): Boolean;
var
  resolvedID: string;
begin
  Result := False;
  EnsureIdentity;
  resolvedID := FConfig.FindContact(recipientID);
  if resolvedID = '' then resolvedID := recipientID;
  FNetwork.Verbose := FVerbose;
  if FNetwork.SendFile(resolvedID, filePath, FIdentity) then
  begin
    writeln('File sent to ', resolvedID);
    Result := True;
  end
  else
    writeln('Failed to send file.');
end;

function TSessionClient.DownloadFile(const URL: string; const KeyHex: string; const savePath: string): Boolean;
var
  Key: array[0..31] of byte;
begin
  Result := False;
  FNetwork.Verbose := FVerbose;
  sessioncrypto.HexToBytes(KeyHex, @Key[0]);
  if FNetwork.DownloadFile(URL, @Key[0], savePath) then
  begin
    writeln('File downloaded to ', savePath);
    Result := True;
  end
  else
    writeln('Failed to download file.');
end;

procedure TSessionClient.ProcessMessageList(msgs: TJSONArray);
var
  i, j, StartIdx: integer;
  B64Data, TimestampStr, MsgHash: string;
  Decrypted: TDecryptedMessage;
  BinaryData: TBytes;
  MsgTime: TDateTime;
  JSONOut: TJSONObject;
  JSONAtchs: TJSONArray;
begin
  if (msgs = nil) or (msgs.Count = 0) then 
  begin
    if FVerbose then writeln(StdErr, 'DEBUG: ProcessMessageList - no messages');
    Exit;
  end;
  
  if FVerbose then writeln(StdErr, 'DEBUG: ProcessMessageList - ', msgs.Count, ' messages');
  
  StartIdx := 0;
  if FLastMessageHash <> '' then
  begin
    for i := msgs.Count - 1 downto 0 do
      if msgs[i].FindPath('hash').AsString = FLastMessageHash then
      begin
        StartIdx := i + 1;
        Break;
      end;
  end;

  for i := StartIdx to msgs.Count - 1 do
  begin
    B64Data := '';
    if msgs[i].FindPath('data') <> nil then
      B64Data := msgs[i].FindPath('data').AsString;
    MsgHash := '';
    if msgs[i].FindPath('hash') <> nil then
      MsgHash := msgs[i].FindPath('hash').AsString;
    
    if FVerbose then writeln(StdErr, 'DEBUG: Message ', i, ' Hash: ', MsgHash, ' DataLen: ', Length(B64Data));
    
    if B64Data <> '' then
    begin
      BinaryData := Base64DecodeBytes(B64Data);
      
      if FVerbose then writeln(StdErr, 'DEBUG: Binary data size: ', Length(BinaryData), ' bytes');
      if FVerbose then writeln(StdErr, 'DEBUG: Binary data hex: ', sessioncrypto.BytesToHex(@BinaryData[0], Length(BinaryData)));
      
      Decrypted := sessioncrypto.DecryptMessage(BinaryData, FIdentity, FVerbose);
      
      if FVerbose then writeln(StdErr, 'DEBUG: Decrypted body: ', Copy(Decrypted.Body, 1, 50));
      
      { Output all messages in JSON mode, even if decryption failed }
      if (FOutputFormat = ofJSON) or (Decrypted.Body <> '[Encrypted Message]') then
      begin
        TimestampStr := msgs[i].FindPath('timestamp').AsString;
        try MsgTime := UnixToDateTime(StrToInt64(TimestampStr) div 1000); except MsgTime := Now; end;

        if FOutputFormat = ofJSON then
        begin
          if FMsgCounter > 0 then write(',');
          Inc(FMsgCounter);
          JSONOut := TJSONObject.Create;
          try
            JSONOut.Add('envelope', TJSONObject.Create([
              'source', Decrypted.Sender,
              'sourceDisplayName', Decrypted.DisplayName,
              'sourceProfilePicURL', Decrypted.ProfilePicURL,
              'timestamp', StrToInt64(TimestampStr),
              'namespace', msgs[i].FindPath('namespace').AsInteger,
              'dataMessage', TJSONObject.Create([
                'timestamp', StrToInt64(TimestampStr),
                'message', Decrypted.Body
              ])
            ]));
            
            if Length(Decrypted.Attachments) > 0 then
            begin
              JSONAtchs := TJSONArray.Create;
              for j := 0 to High(Decrypted.Attachments) do
              begin
                JSONAtchs.Add(TJSONObject.Create([
                  'url', Decrypted.Attachments[j].URL,
                  'key', sessioncrypto.BytesToHex(@Decrypted.Attachments[j].Key[0], Length(Decrypted.Attachments[j].Key)),
                  'digest', sessioncrypto.BytesToHex(@Decrypted.Attachments[j].Digest[0], Length(Decrypted.Attachments[j].Digest)),
                  'fileName', Decrypted.Attachments[j].FileName,
                  'size', Decrypted.Attachments[j].Size
                ]));
              end;
              JSONOut.Objects['envelope'].Objects['dataMessage'].Add('attachments', JSONAtchs);
            end;
            
            writeln(JSONOut.AsJSON);
          finally JSONOut.Free; end;
        end
        else
        begin
          if Decrypted.DisplayName <> '' then
            write(Format('[%s] %s <%s>', [FormatDateTime('yyyy-mm-dd hh:nn:ss', MsgTime), Decrypted.DisplayName, Copy(Decrypted.Sender, 1, 10)]))
          else
            write(Format('[%s] <%s>', [FormatDateTime('yyyy-mm-dd hh:nn:ss', MsgTime), Copy(Decrypted.Sender, 1, 10)]));
            
          if Decrypted.ProfilePicURL <> '' then write(' [Avatar]');
          writeln(': ', Decrypted.Body);
          
          if FVerbose then writeln(StdErr, 'DEBUG: Number of attachments found in message: ', Length(Decrypted.Attachments));
            
          for j := 0 to High(Decrypted.Attachments) do
          begin
            writeln('  [Attachment Received]');
            writeln('    File: ', Decrypted.Attachments[j].FileName);
            writeln('    URL:  ', Decrypted.Attachments[j].URL);
            writeln('    Key:  ', sessioncrypto.BytesToHex(@Decrypted.Attachments[j].Key[0], Length(Decrypted.Attachments[j].Key)));
            writeln('    Digest: ', sessioncrypto.BytesToHex(@Decrypted.Attachments[j].Digest[0], Length(Decrypted.Attachments[j].Digest)));
            writeln('    Size: ', Decrypted.Attachments[j].Size, ' bytes');
          end;
            
          if (Length(Decrypted.Attachments) = 0) and (Pos('http://filev2.getsession.org/file/', Decrypted.Body) > 0) then
            writeln('  [Attachment detected in message body - no key found]');
        end;
      end;
    end;
    FLastMessageHash := MsgHash;
  end;
end;

procedure TSessionClient.PollMessages;
var
  msgs: TJSONArray;
  SavedLastHash: string;
begin
  EnsureIdentity;
  FMsgCounter := 0;
  
  if FOutputFormat = ofJSON then write('[');

  { 1. Receiving NS 0 (Standard messages / Note to Self) }
  if FVerbose then writeln(StdErr, 'DEBUG: Polling Ed25519 NS 0: ', FConfig.SessionID);
  FNetwork.Verbose := FVerbose;
  msgs := FNetwork.RetrieveMessages(FConfig.SessionID, FIdentity.Ed25519SK, 0);
  if (msgs <> nil) then
  begin
    ProcessMessageList(msgs);
    msgs.Free;
  end;

  { 2. X25519 NS 1 (Sync - Sent messages from other devices) }
  SavedLastHash := FLastMessageHash;
  if FVerbose then writeln(StdErr, 'DEBUG: Polling X25519 NS 1 (Sync): ', FConfig.SessionID);
  msgs := FNetwork.RetrieveMessages(FConfig.SessionID, FIdentity.Ed25519SK, 1);
  if (msgs <> nil) then
  begin
    ProcessMessageList(msgs);
    msgs.Free;
  end;
  FLastMessageHash := SavedLastHash;

  { 3. X25519 NS 0 (Note to Self / Legacy Requests) }
  if FVerbose then writeln(StdErr, 'DEBUG: Polling X25519 NS 0 (Note to self): ', FConfig.SessionID);
  msgs := FNetwork.RetrieveMessagesX25519WithEdSK(FConfig.SessionID, FIdentity.Ed25519SK, 0);
  if (msgs <> nil) then
  begin
    ProcessMessageList(msgs);
    msgs.Free;
  end;
  
  if FOutputFormat = ofJSON then writeln(']');
end;

procedure TSessionClient.PullSyncData;
var
  Prof, Cons: Pconfig_object;
  err: array[0..255] of char;
  msgs: TJSONArray;
  B64: string;
  It: Pcontacts_iterator;
  C: Tcontacts_contact;
  Pic: Tuser_profile_pic;
  LatestDump: TBytes;
  i: integer;
  DumpPtr: PByte;
begin
  writeln('Pulling synced data from Session cloud...');

  { 1. Sync Profile (Namespace 2) }
  if FVerbose then writeln(StdErr, 'DEBUG: Retrieving profile from namespace 2 for session: ', FConfig.SessionID);
  SetLength(LatestDump, 0);
  FNetwork.Verbose := FVerbose;
  msgs := FNetwork.RetrieveMessages(FConfig.SessionID, FIdentity.Ed25519SK, 2);
  if (msgs <> nil) and (msgs.Count > 0) then
  begin
    for i := msgs.Count - 1 downto 0 do
    begin
      B64 := '';
      if msgs[i].FindPath('data') <> nil then
        B64 := msgs[i].FindPath('data').AsString;
      if Length(B64) > 10 then
      begin
        LatestDump := Base64DecodeBytes(B64);
        if Length(LatestDump) > 10 then
        begin
          if user_profile_init(@Prof, @FIdentity.Seed[0], @LatestDump[0], Length(LatestDump), @err[0]) = 0 then
          begin
            if FVerbose then writeln(StdErr, 'DEBUG: Found valid profile config in message ', i);
            FConfig.DisplayName := StrPas(user_profile_get_name(Prof));
            Pic := user_profile_get_pic(Prof);
            if StrPas(Pic.url) <> '' then
            begin
              FConfig.ProfilePicURL := StrPas(Pic.url);
              if Pos('#e=', FConfig.ProfilePicURL) > 0 then
                FConfig.ProfilePicKey := Copy(FConfig.ProfilePicURL, Pos('#e=', FConfig.ProfilePicURL) + 3, 64)
              else if Pos('#key=', FConfig.ProfilePicURL) > 0 then
                FConfig.ProfilePicKey := Copy(FConfig.ProfilePicURL, Pos('#key=', FConfig.ProfilePicURL) + 5, 64)
              else
                FConfig.ProfilePicKey := sessioncrypto.BytesToHex(@Pic.key[0], 32);
            end;
            writeln('  [✓] Pulled Display Name: ', FConfig.DisplayName);
            if FConfig.ProfilePicURL <> '' then
              writeln('  [✓] Pulled Profile Pic URL: ', FConfig.ProfilePicURL);
            config_free(Prof);
            Break;
          end;
        end;
      end;
    end;
    msgs.Free;
  end;

  { 2. Pull Contacts (NS 1) }
  SetLength(LatestDump, 0);
  msgs := FNetwork.RetrieveMessages(FConfig.SessionID, FIdentity.Ed25519SK, 1);
  if (msgs <> nil) and (msgs.Count > 0) then
  begin
    B64 := msgs[msgs.Count-1].FindPath('data').AsString;
    if B64 <> '' then
      LatestDump := Base64DecodeBytes(B64);
    msgs.Free;
  end;

  if Length(LatestDump) > 0 then DumpPtr := @LatestDump[0] else DumpPtr := nil;

  if contacts_init(@Cons, @FIdentity.Seed[0], DumpPtr, Length(LatestDump), @err[0]) = 0 then
  begin
    It := contacts_iterator_new(Cons);
    while not contacts_iterator_done(It, @C) do
    begin
      FConfig.AddContact(StrPas(C.name), StrPas(C.session_id));
      contacts_iterator_advance(It);
    end;
    contacts_iterator_free(It);
    writeln('  [✓] Pulled ', contacts_size(Cons), ' contacts');
    config_free(Cons);
  end;
  
  FConfig.Save;
end;

procedure TSessionClient.Sync;
var
  Prof, Cons: Pconfig_object;
  err: array[0..255] of char;
  Contact: Tcontacts_contact;
  Pic: Tuser_profile_pic;
  i: integer;
  msgs: TJSONArray;
  B64: string;
  LatestDump: TBytes;
  DumpPtr: PByte;
begin
  EnsureIdentity;
  writeln('Synchronizing profile and contacts to Session network...');
  
  { 1. Sync Profile (Namespace 2) }
  if FVerbose then writeln(StdErr, 'DEBUG: Retrieving profile from namespace 2 for session: ', FConfig.SessionID);
  SetLength(LatestDump, 0);
  FNetwork.Verbose := FVerbose;
  msgs := FNetwork.RetrieveMessages(FConfig.SessionID, FIdentity.Ed25519SK, 2);
  if (msgs <> nil) and (msgs.Count > 0) then
  begin
    for i := msgs.Count - 1 downto 0 do
    begin
      B64 := '';
      if msgs[i].FindPath('data') <> nil then
        B64 := msgs[i].FindPath('data').AsString;
      if Length(B64) > 10 then
      begin
        LatestDump := Base64DecodeBytes(B64);
        if Length(LatestDump) > 10 then
        begin
          if user_profile_init(@Prof, @FIdentity.Seed[0], @LatestDump[0], Length(LatestDump), @err[0]) = 0 then
          begin
            if FVerbose then writeln(StdErr, 'DEBUG: Found valid profile config in message ', i);
            Break;
          end;
        end;
      end;
    end;
    msgs.Free;
  end;

  if Length(LatestDump) > 0 then DumpPtr := @LatestDump[0] else DumpPtr := nil;

  if user_profile_init(@Prof, @FIdentity.Seed[0], DumpPtr, Length(LatestDump), @err[0]) = 0 then
  begin
    user_profile_set_name(Prof, PChar(FConfig.DisplayName));
    
    if FConfig.ProfilePicURL <> '' then
    begin
      FillChar(Pic, SizeOf(Pic), 0);
      StrPCopy(Pic.url, FConfig.ProfilePicURL);
      if FConfig.ProfilePicKey <> '' then
        sessioncrypto.HexToBytes(FConfig.ProfilePicKey, @Pic.key[0])
      else
        Move(FIdentity.ProfileKey[0], Pic.key[0], 32);
      
      user_profile_set_pic(Prof, Pic);
      user_profile_set_reupload_pic(Prof, Pic);
    end;

    if FVerbose then 
    begin
      writeln(StdErr, 'DEBUG: Profile name set to: ', FConfig.DisplayName);
      if FConfig.ProfilePicURL <> '' then writeln(StdErr, 'DEBUG: Profile pic URL set to: ', FConfig.ProfilePicURL);
      writeln(StdErr, 'DEBUG: Profile get_name returns: ', StrPas(user_profile_get_name(Prof)));
      writeln(StdErr, 'DEBUG: Profile needs_push: ', config_needs_push(Prof));
    end;

    if not config_needs_push(Prof) then
    begin
      if FVerbose then writeln(StdErr, 'DEBUG: Profile already in sync (no changes needed)');
      config_free(Prof);
    end
    else if FNetwork.StoreConfig(Prof, FConfig.SessionID, FIdentity.Ed25519SK) then
    begin
      writeln('  [✓] Profile synced (Namespace 2)');
      config_free(Prof);
    end
    else writeln('  [✗] Profile sync failed');
  end else writeln('  [✗] Failed to init profile config: ', string(err));

  { 2. Sync Contacts (Namespace 1) }
  SetLength(LatestDump, 0);
  msgs := FNetwork.RetrieveMessages(FConfig.SessionID, FIdentity.Ed25519SK, 1);
  if (msgs <> nil) and (msgs.Count > 0) then
  begin
    B64 := msgs[msgs.Count-1].FindPath('data').AsString;
    if B64 <> '' then
      LatestDump := Base64DecodeBytes(B64);
    msgs.Free;
  end;

  if Length(LatestDump) > 0 then DumpPtr := @LatestDump[0] else DumpPtr := nil;

  if contacts_init(@Cons, @FIdentity.Seed[0], DumpPtr, Length(LatestDump), @err[0]) = 0 then
  begin
    for i := 0 to High(FConfig.Contacts) do
    begin
      FillChar(Contact, SizeOf(Contact), 0);
      StrPCopy(Contact.name, FConfig.Contacts[i].Name);
      StrPCopy(Contact.session_id, FConfig.Contacts[i].SessionID);
      contacts_set(Cons, @Contact);
    end;
    
    if not config_needs_push(Cons) then
    begin
      if FVerbose then writeln(StdErr, 'DEBUG: Contacts already in sync');
    end
    else if FNetwork.StoreConfig(Cons, FConfig.SessionID, FIdentity.Ed25519SK) then
      writeln('  [✓] Contacts synced (Namespace 1)')
    else
      writeln('  [✗] Contacts sync failed');
    config_free(Cons);
  end else writeln('  [✗] Failed to init contacts config: ', string(err));
end;

procedure TSessionClient.DeleteMessages(const Hashes: array of string);
begin
  if FNetwork.DeleteMessages(FConfig.SessionID, FIdentity.Ed25519SK, Hashes) then
    writeln('Successfully deleted ', Length(Hashes), ' messages from swarm.')
  else
    writeln('Failed to delete messages.');
end;

procedure TSessionClient.SetDisplayName(const NewName: string);
begin
  FConfig.DisplayName := NewName;
  FConfig.Save;
  writeln('Display name set to: ', NewName);
end;

procedure TSessionClient.SetProfilePicture(const FilePath: string);
var
  URL, DummyDigest: string;
  Key: TBytes;
begin
  EnsureIdentity;
  FNetwork.Verbose := FVerbose;
  writeln('Uploading profile picture: ', FilePath, '...');
  if FNetwork.UploadFile(FilePath, FIdentity, URL, Key, DummyDigest, True) then
  begin
    FConfig.ProfilePicURL := URL; // URL already includes #p fragment now
    FConfig.ProfilePicKey := sessioncrypto.BytesToHex(@Key[0], 32);
    FConfig.Save;
    writeln('Profile picture uploaded successfully.');
    writeln('URL: ', URL);
    Sync;
  end
  else
    writeln('Failed to upload profile picture.');
end;

procedure TSessionClient.AddContact(const name, sessionID: string);
begin
  FConfig.AddContact(name, sessionID);
end;

procedure TSessionClient.RemoveContact(const name: string);
begin
  FConfig.RemoveContact(name);
end;

procedure TSessionClient.ListContacts;
var I: Integer;
begin
  WriteLn('Contacts:');
  for I := 0 to High(FConfig.Contacts) do
    WriteLn(Format('  %-20s %s', [FConfig.Contacts[I].Name, FConfig.Contacts[I].SessionID]));
end;

function TSessionClient.ResolveONS(const Name: string): string;
begin
  Result := FNetwork.OnsResolve(Name);
end;

function TSessionClient.RequestList: TJSONArray;
var
  msgs, resultArr: TJSONArray;
  i, j: integer;
  sender: string;
  found: boolean;
  binData: TBytes;
  decrypted: TDecryptedMessage;
begin
  resultArr := TJSONArray.Create;
  Result := resultArr;
  
  { Poll X25519 for potential requests }
  msgs := FNetwork.RetrieveMessagesX25519WithEdSK(FConfig.SessionID, FIdentity.Ed25519SK, 0);
  if msgs <> nil then
  begin
    for i := 0 to msgs.Count - 1 do
    begin
      binData := Base64DecodeBytes(msgs[i].FindPath('data').AsString);

      decrypted := sessioncrypto.DecryptMessage(binData, FIdentity, FVerbose);
      sender := decrypted.Sender;
      
      if sender <> 'Unknown' then
      begin
        found := False;
        for j := 0 to High(FConfig.Contacts) do
          if FConfig.Contacts[j].SessionID = sender then
          begin
            found := True;
            Break;
          end;
          
        if not found then
        begin
          found := False;
          for j := 0 to resultArr.Count - 1 do
            if resultArr.Objects[j].Strings['sender'] = sender then
            begin
              found := True;
              Break;
            end;
            
          if not found then
            resultArr.Add(TJSONObject.Create(['sender', sender, 'message', decrypted.Body]));
        end;
      end;
    end;
    msgs.Free;
  end;
end;

procedure TSessionClient.AcceptRequest(const sessionID: string; const name: string = '');
var
  resolvedName: string;
begin
  if name <> '' then resolvedName := name else resolvedName := Copy(sessionID, 1, 10);
  FConfig.AddContact(resolvedName, sessionID, True);
  Sync; // Push updated contacts to cloud
  writeln('Accepted request from ', sessionID, ' as ', resolvedName);
end;

function TSessionClient.CleanProfileNamespace: Boolean;
begin
  Result := False;
  FNetwork.Verbose := FVerbose;
  
  writeln('Deleting all messages from namespace 2...');
  Result := FNetwork.DeleteAllMessages(FConfig.SessionID, FIdentity.Ed25519SK, 2);
end;

end.
