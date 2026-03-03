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

unit sessionnetwork;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fphttpclient, fpjson, jsonparser, sessionconfig, sessioncrypto, libsession, ctypes, DateUtils, base64, zmq_utils, sslsockets, ssockets;

type
  TSessionNetwork = class
  private
    FConfig: TSessionConfig;
    FVerbose: Boolean;
    procedure DoGetSocketHandler(Sender: TObject; const UseSSL: Boolean; out AHandler: TSocketHandler);
    function InternalRequest(const Request: TJSONObject): string;
    function InternalOnionRequest(const Host, Endpoint, Method: string; const Payload: TBytes; const ServerPK: string): string;
    procedure ProcessSwarmResponse(JSON: TJSONData);
  public
    constructor Create(AConfig: TSessionConfig);
    
    function GetSwarm(const sessionID: string; Namespace: Integer = 0): Boolean;
    function StoreMessage(const recipientID, ciphertext: string; const SK: TSessionSK): Boolean;
    function StoreConfig(const Config: Pconfig_object; const sessionID: string; const EdSK: TSessionSK): Boolean;
    function RetrieveMessages(const sessionID: string; const EdSK: TSessionSK; Namespace: Integer): TJSONArray;
    function RetrieveMessagesX25519WithEdSK(const sessionID: string; const EdSK: TSessionSK; Namespace: Integer): TJSONArray;
    function OnsResolve(const Name: string): string;
    function DeleteMessages(const sessionID: string; const EdSK: TSessionSK; const Hashes: array of string; Namespace: Integer = 0): Boolean;
    function DeleteAllMessages(const sessionID: string; const EdSK: TSessionSK; Namespace: Integer): Boolean;
    
    function SendFile(const RecipientID: string; const FilePath: string; const Identity: TSessionIdentity): Boolean;
    function UploadFile(const FilePath: string; const Identity: TSessionIdentity; out URL: string; out Key: TBytes; out DigestHex: string; IsProfilePic: Boolean = False): Boolean;
    function DownloadFile(const URL: string; const Key: pointer; const SavePath: string): Boolean;

    property Verbose: Boolean read FVerbose write FVerbose;
  end;

implementation

procedure TSessionNetwork.ProcessSwarmResponse(JSON: TJSONData);
var
  Nodes: TJSONArray;
  I: Integer;
begin
  Nodes := TJSONArray(JSON.FindPath('snodes'));
  if (Nodes = nil) then Nodes := TJSONArray(JSON.FindPath('result.snodes'));
  
  if (Nodes <> nil) and (Nodes.Count > 0) then
  begin
    FConfig.ClearSwarmNodes;
    for I := 0 to Nodes.Count - 1 do
    begin
      if Nodes[I].FindPath('ip') <> nil then
        FConfig.AddSwarmNode(Nodes[I].FindPath('ip').AsString, StrToIntDef(Nodes[I].FindPath('port').AsString, 22021))
      else if Nodes[I].FindPath('public_ip') <> nil then
        FConfig.AddSwarmNode(Nodes[I].FindPath('public_ip').AsString, Nodes[I].FindPath('storage_port').AsInteger);
      
      if Nodes[I].FindPath('pubkey_x25519') <> nil then
        FConfig.SwarmNodes[High(FConfig.SwarmNodes)].PubKey := Nodes[I].FindPath('pubkey_x25519').AsString;
    end;
  end;
end;

constructor TSessionNetwork.Create(AConfig: TSessionConfig);
begin
  FConfig := AConfig;
end;

procedure TSessionNetwork.DoGetSocketHandler(Sender: TObject; const UseSSL: Boolean; out AHandler: TSocketHandler);
begin
  AHandler := nil;
  if UseSSL then
  begin
    AHandler := TSSLSocketHandler.GetDefaultHandler;
    TSSLSocketHandler(AHandler).VerifyPeerCert := False;
  end;
end;

function TSessionNetwork.InternalRequest(const Request: TJSONObject): string;
var
  Http: TFPHTTPClient;
  Resp: string;
  URL: string;
  i, RetryCount: integer;
  NodesToTry: TSwarmNodeArray;
  JSON: TJSONData;
begin
  Result := '';
  for RetryCount := 0 to 2 do
  begin
    if Length(FConfig.SwarmNodes) = 0 then
    begin
      if not GetSwarm(FConfig.SessionID) then 
      begin
        { If GetSwarm failed, the ID might be too new for seeds. 
          Use initial stable nodes from config as last resort. }
        if FVerbose then writeln(StdErr, 'DEBUG: GetSwarm failed. Using initial stable nodes.');
        FConfig.Load; // Reload defaults
      end;
      if Length(FConfig.SwarmNodes) = 0 then Exit;
    end;

    { Copy current swarm to local array to avoid issues if FConfig changes mid-loop }
    SetLength(NodesToTry, Length(FConfig.SwarmNodes));
    for i := 0 to High(FConfig.SwarmNodes) do NodesToTry[i] := FConfig.SwarmNodes[i];

    Http := TFPHTTPClient.Create(nil);
    try
      Http.OnGetSocketHandler := @DoGetSocketHandler;
      Http.AddHeader('Content-Type', 'application/json');
      Http.ConnectTimeout := 5000;
      Http.IOTimeout := 5000;
      
      Http.RequestBody := TStringStream.Create(Request.AsJSON);
      try
        for i := 0 to High(NodesToTry) do
        begin
          URL := 'https://' + NodesToTry[i].Host + ':' + IntToStr(NodesToTry[i].Port) + '/storage_rpc/v1';
          if FVerbose then writeln(StdErr, 'DEBUG: Requesting ', URL, ' (Method: ', Request.FindPath('method').AsString, ')');
          try
            Http.RequestBody.Position := 0;
            Resp := Http.Post(URL);
            if Resp <> '' then
            begin
              Result := Resp; { Success by default if we got SOMETHING back }
              JSON := GetJSON(Resp);
              try
                if (JSON.FindPath('snodes') <> nil) or (JSON.FindPath('result.snodes') <> nil) then
                begin
                  if FVerbose then writeln(StdErr, 'DEBUG: Node returned new swarm list (Redirect). Updating and retrying...');
                  ProcessSwarmResponse(JSON);
                  Result := ''; { Force retry with new swarm }
                  Break; 
                end;
              finally
                JSON.Free;
              end;
              if Result <> '' then Break; { Real success }
            end;
          except
            on E: Exception do
              if FVerbose then writeln(StdErr, 'DEBUG: Request to node ', i, ' failed: ', E.Message);
          end;
        end;
      finally
        Http.RequestBody.Free;
        Http.RequestBody := nil;
      end;
    finally
      Http.Free;
    end;
    
    if Result <> '' then Break;
    if FVerbose then writeln(StdErr, 'DEBUG: Retry ', RetryCount + 1, ' for request...');
  end;
end;

function TSessionNetwork.InternalOnionRequest(const Host, Endpoint, Method: string; const Payload: TBytes; const ServerPK: string): string;
var
  Http: TFPHTTPClient;
  builder: Ponion_request_builder;
  payload_out: Punsigned_char;
  payload_out_len: csize_t;
  final_xpk, final_xsk: array[0..31] of byte;
  PostData: TStringStream;
  FullURL, Resp: string;
begin
  Result := '';
  onion_request_builder_init(@builder);
  try
    onion_request_builder_set_enc_type(builder, ENCRYPT_TYPE_X_CHA_CHA_20);
    onion_request_builder_set_server_destination(builder, 'http', PChar(Host), PChar(Endpoint), PChar(Method), 22021, PChar(ServerPK));
    
    if onion_request_builder_build(builder, @Payload[0], Length(Payload), @payload_out, @payload_out_len, @final_xpk[0], @final_xsk[0]) then
    begin
      Http := TFPHTTPClient.Create(nil);
      try
        Http.OnGetSocketHandler := @DoGetSocketHandler;
        Http.ConnectTimeout := 10000;
        Http.IOTimeout := 10000;
        Http.AddHeader('Content-Type', 'application/octet-stream');
        FullURL := 'https://' + Host + ':22021/onion_request/v2';
        PostData := TStringStream.Create('');
        try
          PostData.Write(payload_out^, payload_out_len);
          PostData.Position := 0;
          Http.RequestBody := PostData;
          Resp := Http.Post(FullURL);
          Result := Resp;
        finally
          PostData.Free;
        end;
      finally
        Http.Free;
        if payload_out <> nil then libsession.free(payload_out);
      end;
    end;
  finally
    onion_request_builder_free(builder);
  end;
end;

function TSessionNetwork.GetSwarm(const sessionID: string; Namespace: Integer = 0): Boolean;
var
  Http: TFPHTTPClient;
  Req, Resp: string;
  JSON: TJSONData;
  Nodes: TJSONArray;
  I, J: Integer;
begin
  Result := False;
  Http := TFPHTTPClient.Create(nil);
  try
    Http.OnGetSocketHandler := @DoGetSocketHandler;
    Http.ConnectTimeout := 10000;
    Http.IOTimeout := 10000;
    Http.AddHeader('Content-Type', 'application/json');
    
    Req := '{"jsonrpc":"2.0","id":1,"method":"get_n_service_nodes","params":{"n":10}}';
    if FVerbose then WriteLn(StdErr, 'DEBUG: GetSwarm Request: ', Req);
    for J := 1 to 3 do
    begin
      try
        Http.RequestBody := TStringStream.Create(Req);
        try Resp := Http.Post('https://seed' + IntToStr(J) + '.getsession.org/json_rpc');
        finally Http.RequestBody.Free; Http.RequestBody := nil; end;
        
        if Resp <> '' then
        begin
          if FVerbose then WriteLn(StdErr, 'DEBUG: Seed Response: ', Resp);
          JSON := GetJSON(Resp);
          try
            Nodes := TJSONArray(JSON.FindPath('result.service_node_states'));
            if (Nodes <> nil) and (Nodes.Count > 0) then
            begin
              FConfig.ClearSwarmNodes;
              for I := 0 to Nodes.Count - 1 do
              begin
                if Nodes[I].FindPath('storage_port') <> nil then
                  FConfig.AddSwarmNode(Nodes[I].FindPath('public_ip').AsString, Nodes[I].FindPath('storage_port').AsInteger)
                else
                  FConfig.AddSwarmNode(Nodes[I].FindPath('public_ip').AsString, 22021);
                
                if Nodes[I].FindPath('pubkey_x25519') <> nil then
                  FConfig.SwarmNodes[High(FConfig.SwarmNodes)].PubKey := Nodes[I].FindPath('pubkey_x25519').AsString;
              end;
              Result := True;
              Break;
            end;
          finally JSON.Free; end;
        end;
      except
      end;
    end;
  finally
    Http.Free;
  end;
end;

function TSessionNetwork.StoreMessage(const recipientID, ciphertext: string; const SK: TSessionSK): Boolean;
var
  request, params: TJSONObject;
  timestamp: QWord;
  resp, B64Data: string;
begin
  Result := False;
  B64Data := EncodeStringBase64(ciphertext);
  timestamp := Int64(DateTimeToUnix(LocalTimeToUniversal(Now))) * 1000;
  request := TJSONObject.Create;
  try
    request.Add('jsonrpc', '2.0'); request.Add('id', 1); request.Add('method', 'store');
    params := TJSONObject.Create;
    params.Add('pubkey', recipientID); 
    params.Add('namespace', 0);
    params.Add('data', B64Data);
    params.Add('timestamp', timestamp); 
    params.Add('ttl', 86400000); request.Add('params', params);
    if FVerbose then WriteLn(StdErr, 'DEBUG: StoreMessage Request: ', request.AsJSON);
    resp := InternalRequest(request);
    if FVerbose then WriteLn(StdErr, 'DEBUG: StoreMessage Response: ', resp);
    if resp <> '' then Result := True;
  finally request.Free; end;
end;

function TSessionNetwork.StoreConfig(const Config: Pconfig_object; const sessionID: string; const EdSK: TSessionSK): Boolean;
var
  dump: Punsigned_char; dumplen: csize_t; B64Data: string;
  request, params: TJSONObject; timestamp: QWord;
  sigPayload, signature: string; NS: Integer; EdPK: TSessionPK;
  B64Bytes: TBytes;
begin
  Result := False; if not config_dump(Config, @dump, @dumplen) then Exit;
  SetLength(B64Bytes, dumplen);
  Move(dump^, B64Bytes[0], dumplen);
  B64Data := zmq_utils.Base64EncodeBytes(B64Bytes);
  libsession.free(dump);
  NS := config_storage_namespace(Config);
  timestamp := Int64(DateTimeToUnix(LocalTimeToUniversal(Now))) * 1000;
  sigPayload := 'store' + B64Data + IntToStr(NS) + IntToStr(timestamp);
  signature := sessioncrypto.SignDataB64(EdSK, sigPayload);
  Move(EdSK[32], EdPK[0], 32);
  request := TJSONObject.Create;
  try
    request.Add('jsonrpc', '2.0'); request.Add('id', 1); request.Add('method', 'store');
    params := TJSONObject.Create;
    params.Add('pubkey', sessionID); params.Add('pubkey_ed25519', sessioncrypto.BytesToHex(@EdPK[0], 32));
    params.Add('namespace', NS); params.Add('data', B64Data);
    params.Add('timestamp', timestamp); params.Add('signature', signature);
    request.Add('params', params);
    if InternalRequest(request) <> '' then Result := True;
  finally request.Free; end;
end;

function TSessionNetwork.RetrieveMessages(const sessionID: string; const EdSK: TSessionSK; Namespace: Integer): TJSONArray;
var
  request, params: TJSONObject; resp: string; RespJSON: TJSONData;
  timestamp: QWord; sigPayload, signature: string; EdPK: TSessionPK;
  i: Integer;
begin
  Result := nil; if not GetSwarm(sessionID) then Exit;
  Move(EdSK[32], EdPK[0], 32);
  timestamp := Int64(DateTimeToUnix(LocalTimeToUniversal(Now))) * 1000;
  if Namespace = 0 then sigPayload := 'retrieve' + IntToStr(timestamp)
  else sigPayload := 'retrieve' + IntToStr(Namespace) + IntToStr(timestamp);
  if FVerbose then WriteLn(StdErr, 'DEBUG: sigPayload: ', sigPayload);
  signature := sessioncrypto.SignDataB64(EdSK, sigPayload);
  request := TJSONObject.Create;
  try
    request.Add('jsonrpc', '2.0'); request.Add('id', 1); request.Add('method', 'retrieve');
    params := TJSONObject.Create;
    params.Add('pubkey', sessionID); params.Add('pubkey_ed25519', sessioncrypto.BytesToHex(@EdPK[0], 32));
    params.Add('timestamp', timestamp); params.Add('signature', signature);
    params.Add('namespace', Namespace); request.Add('params', params);
    if FVerbose then WriteLn(StdErr, 'DEBUG: RetrieveMessages Request (NS=', Namespace, '): ', request.AsJSON);
    resp := InternalRequest(request);
    if FVerbose then WriteLn(StdErr, 'DEBUG: RetrieveMessages Response: ', resp);
    if Resp <> '' then begin
      if FVerbose then WriteLn(StdErr, 'DEBUG: RetrieveMessages Response (Raw): ', Resp);
      RespJSON := GetJSON(Resp);
      try
        { Check both result.messages and top-level messages }
        if (RespJSON.FindPath('result.messages') <> nil) then
          Result := TJSONArray(RespJSON.FindPath('result.messages').Clone)
        else if (RespJSON.FindPath('messages') <> nil) then
          Result := TJSONArray(RespJSON.FindPath('messages').Clone);
          
        if (Result <> nil) then
        begin
          { Inject namespace into each message }
          for i := 0 to Result.Count - 1 do
            TJSONObject(Result[i]).Add('namespace', Namespace);
        end;
      finally RespJSON.Free; end;
    end;
  finally request.Free; end;
end;

function TSessionNetwork.RetrieveMessagesX25519WithEdSK(const sessionID: string; const EdSK: TSessionSK; Namespace: Integer): TJSONArray;
var
  EdPK: TSessionPK;
  XPK: TSessionXPK;
  XPK_Hex: string;
begin
  { For X25519 retrieval, the pubkey parameter must be the X25519 public key (05... hex) }
  Move(EdSK[32], EdPK[0], 32);
  sessioncrypto.crypto_sign_ed25519_pk_to_curve25519(@XPK[0], @EdPK[0]);
  XPK_Hex := '05' + LowerCase(sessioncrypto.BytesToHex(@XPK[0], 32));
  
  if FVerbose then WriteLn(StdErr, 'DEBUG: RetrieveMessagesX25519 - Using XPK: ', XPK_Hex);
  Result := RetrieveMessages(XPK_Hex, EdSK, Namespace);
end;

function TSessionNetwork.OnsResolve(const Name: string): string;
var
  Http: TFPHTTPClient;
  Req, Resp: string;
  JSON: TJSONData;
  J: Integer;
  SeedNodes: array[0..2] of string = ('https://seed1.getsession.org/json_rpc', 'https://seed2.getsession.org/json_rpc', 'https://seed3.getsession.org/json_rpc');
begin
  Result := ''; Http := TFPHTTPClient.Create(nil);
  try
    Http.OnGetSocketHandler := @DoGetSocketHandler;
    Http.ConnectTimeout := 10000;
    Http.IOTimeout := 10000;
    Req := '{"jsonrpc":"2.0","id":1,"method":"ons_resolve","params":{"name":"' + Name + '","type":0}}';
    for J := 0 to High(SeedNodes) do
    begin
      try
        Http.RequestBody := TStringStream.Create(Req);
        try
          Resp := Http.Post(SeedNodes[J]);
        finally
          Http.RequestBody.Free;
          Http.RequestBody := nil;
        end;
        JSON := GetJSON(Resp);
        try
          if JSON.FindPath('result.session_id') <> nil then
          begin
            Result := JSON.FindPath('result.session_id').AsString;
            Break;
          end;
        finally JSON.Free; end;
      except end;
    end;
  finally Http.Free; end;
end;

function TSessionNetwork.DeleteMessages(const sessionID: string; const EdSK: TSessionSK; const Hashes: array of string; Namespace: Integer = 0): Boolean;
var request, params: TJSONObject; HashesArr: TJSONArray; I: Integer;
begin
  Result := False; request := TJSONObject.Create;
  try
    request.Add('jsonrpc', '2.0'); request.Add('id', 1); request.Add('method', 'delete');
    params := TJSONObject.Create; params.Add('pubkey', sessionID); params.Add('namespace', Namespace);
    HashesArr := TJSONArray.Create; for I := 0 to High(Hashes) do HashesArr.Add(Hashes[I]);
    params.Add('messages', HashesArr); request.Add('params', params);
    if InternalRequest(request) <> '' then Result := True;
  finally request.Free; end;
end;

function TSessionNetwork.DeleteAllMessages(const sessionID: string; const EdSK: TSessionSK; Namespace: Integer): Boolean;
var
  request, params: TJSONObject; timestamp: QWord;
  sigPayload, signature: string; EdPK: TSessionPK;
begin
  Result := False; if not GetSwarm(sessionID) then Exit;
  Move(EdSK[32], EdPK[0], 32);
  timestamp := Int64(DateTimeToUnix(LocalTimeToUniversal(Now))) * 1000;
  if Namespace = 0 then sigPayload := 'delete_all' + IntToStr(timestamp)
  else sigPayload := 'delete_all' + IntToStr(Namespace) + IntToStr(timestamp);
  signature := sessioncrypto.SignDataB64(EdSK, sigPayload);
  request := TJSONObject.Create;
  try
    request.Add('jsonrpc', '2.0'); request.Add('id', 1); request.Add('method', 'delete_all');
    params := TJSONObject.Create;
    params.Add('pubkey', sessionID); params.Add('pubkey_ed25519', sessioncrypto.BytesToHex(@EdPK[0], 32));
    params.Add('timestamp', timestamp); params.Add('signature', signature);
    params.Add('namespace', Namespace); request.Add('params', params);
    if InternalRequest(request) <> '' then Result := True;
  finally request.Free; end;
end;

function TSessionNetwork.SendFile(const RecipientID: string; const FilePath: string; const Identity: TSessionIdentity): Boolean;
var
  URL, DigestHex: string; Key: TBytes;
begin
  Result := UploadFile(FilePath, Identity, URL, Key, DigestHex, False);
end;

function TSessionNetwork.UploadFile(const FilePath: string; const Identity: TSessionIdentity; out URL: string; out Key: TBytes; out DigestHex: string; IsProfilePic: Boolean = False): Boolean;
var
  Http: TFPHTTPClient; FileStream: TFileStream;
  Plaintext, Encrypted: TBytes; FileID, HttpResp: string;
  ReplyJSON: TJSONData; PostData: TStringStream;
  err: array[0..255] of char;
  enc_size: csize_t;
  DigestBytes: array[0..31] of byte;
begin
  Result := False; URL := ''; DigestHex := '';
  if not FileExists(FilePath) then exit;
  FileStream := TFileStream.Create(FilePath, fmOpenRead);
  try
    SetLength(Plaintext, FileStream.Size);
    FileStream.Read(Plaintext[0], FileStream.Size);
  finally FileStream.Free; end;

  SetLength(Key, 32);
  if IsProfilePic then begin
    if not sessioncrypto.EncryptAESGCM(Plaintext, Key, Encrypted) then exit;
  end else begin
    enc_size := session_attachment_encrypted_size(Length(Plaintext));
    SetLength(Encrypted, enc_size);
    session_attachment_encrypt(@Identity.Seed[0], @Plaintext[0], Length(Plaintext), ATTACHMENT_DOMAIN_ATTACHMENT, @Key[0], @Encrypted[0], @err[0]);
  end;

  crypto_hash_sha256(@DigestBytes[0], @Encrypted[0], Length(Encrypted));
  DigestHex := sessioncrypto.BytesToHex(@DigestBytes[0], 32);

  Http := TFPHTTPClient.Create(nil);
  try
    Http.OnGetSocketHandler := @DoGetSocketHandler;
    Http.ConnectTimeout := 30000;
    Http.IOTimeout := 30000;
    Http.AddHeader('Content-Type', 'application/octet-stream');
    PostData := TStringStream.Create('');
    try
      PostData.Write(Encrypted[0], Length(Encrypted)); PostData.Position := 0;
      Http.RequestBody := PostData;
      HttpResp := Http.Post('https://filev2.getsession.org/file');
      ReplyJSON := GetJSON(HttpResp);
      try
        FileID := ReplyJSON.FindPath('id').AsString;
        URL := 'https://filev2.getsession.org/file/' + FileID + '#p=b8eef9821445ae16e2e97ef8aa6fe782fd11ad5253cd6723b281341dba22e371';
        Result := True;
      finally ReplyJSON.Free; end;
    finally PostData.Free; end;
  finally Http.Free; end;
end;

function TSessionNetwork.DownloadFile(const URL: string; const Key: pointer; const SavePath: string): Boolean;
var
  Http: TFPHTTPClient;
  Encrypted, Decrypted: TBytes;
  BareURL: string;
  RespStream: TMemoryStream;
begin
  Result := False;
  BareURL := URL;
  if Pos('#', BareURL) > 0 then BareURL := Copy(BareURL, 1, Pos('#', BareURL) - 1);
  
  Http := TFPHTTPClient.Create(nil);
  Http.OnGetSocketHandler := @DoGetSocketHandler;
  Http.ConnectTimeout := 30000;
  Http.IOTimeout := 30000;
  RespStream := TMemoryStream.Create;
  try
    try
      Http.Get(BareURL, RespStream);
      SetLength(Encrypted, RespStream.Size);
      RespStream.Position := 0;
      RespStream.Read(Encrypted[0], RespStream.Size);
      
      if sessioncrypto.DecryptedAttachmentBody(Encrypted, TBytes(Key), Decrypted) then
      begin
        with TFileStream.Create(SavePath, fmCreate) do
        try Write(Decrypted[0], Length(Decrypted)); finally Free; end;
        Result := True;
      end;
    except
    end;
  finally
    Http.Free;
    RespStream.Free;
  end;
end;

end.
