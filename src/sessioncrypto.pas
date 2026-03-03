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

unit sessioncrypto;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, libsession, ctypes, base64, DateUtils;

type
  TSessionSeed = array[0..31] of byte;
  TSessionPK = array[0..31] of byte;
  TSessionSK = array[0..63] of byte;
  TSessionXPK = array[0..31] of byte;
  TSessionXSK = array[0..31] of byte;

  TSessionIdentity = record
    Seed: TSessionSeed;
    Ed25519PK: TSessionPK;
    Ed25519SK: TSessionSK;
    X25519PK: TSessionXPK;
    X25519SK: TSessionXSK;
    ProSK: TSessionSK;
    ProfileKey: TSessionPK;
    SessionID: string;
  end;

  TAttachment = record
    Key: TBytes;
    URL: string;
    Digest: TBytes;
    FileName: string;
    Size: QWord;
  end;
  TAttachmentArray = array of TAttachment;

  TDecryptedMessage = record
    Sender: string;
    DisplayName: string;
    ProfilePicURL: string;
    Body: string;
    Attachments: TAttachmentArray;
    Timestamp: QWord;
  end;

function GenerateSeed: TSessionSeed;
function GetSessionID(const pk: TSessionPK): string;
function GetEd25519SessionID(const pk: TSessionPK): string;
function GetX25519DerivedEd25519SessionID(const xpk: TSessionXPK): string;
procedure DeriveKeyPair(const seed: TSessionSeed; out pk: TSessionPK; out sk: TSessionSK);
procedure DeriveKeyPair16(const seed: array of byte; out pk: TSessionPK; out sk: TSessionSK);
procedure DeriveX25519(var Identity: TSessionIdentity);

procedure GenerateNewIdentity(out Identity: TSessionIdentity);
function LoadIdentity(const SeedPath: string; out Identity: TSessionIdentity): Boolean;
function SaveIdentity(const SeedPath: string; const Identity: TSessionIdentity): Boolean;

function SignData(const sk: TSessionSK; const Data: string): string;
function SignDataB64(const sk: TSessionSK; const Data: string): string;
function SignDataB64_X25519(const xsk: TSessionXSK; const Data: string): string;
function EncryptAESGCM(const Plaintext: TBytes; const Key: TBytes; out Ciphertext: TBytes): Boolean;
function EncodeContent(const Body: string; Timestamp: QWord; const DisplayName: string; const ProfileKey: TSessionPK; const ProfilePicURL: string = ''; const Attachments: TAttachmentArray = nil): TBytes;
function EncryptMessage(const Plaintext: string; const RecipientSessionID: string; const Identity: TSessionIdentity; const DisplayName: string; const ProfilePicURL: string = ''; const ProfileKeyHex: string = ''; const Attachments: TAttachmentArray = nil): string;
function DecryptedAttachmentBody(const Data: TBytes; const Key: TBytes; var Output: TBytes): Boolean;
function DecryptMessage(const EncryptedBytes: TBytes; const Identity: TSessionIdentity; Verbose: Boolean = False): TDecryptedMessage;

function crypto_sign_ed25519_pk_to_curve25519(x_pk_out: pointer; ed_pk_in: pointer): Integer; cdecl; external libsession.LIB_SESSION_CRYPTO;
function crypto_sign_ed25519_sk_to_curve25519(x_sk_out: pointer; ed_sk_in: pointer): Integer; cdecl; external libsession.LIB_SESSION_CRYPTO;

function BytesToHex(const Bytes: pointer; Len: Integer): string;
procedure HexToBytes(const Hex: string; Buf: pointer);

implementation

function GenerateSeed: TSessionSeed;
begin
  sodium_init();
  FillChar(Result[0], 32, 0);
  randombytes_buf(@Result[0], 16);
end;

function GetSessionID(const pk: TSessionPK): string;
begin
  result := '05' + LowerCase(BytesToHex(@pk[0], 32));
end;

function GetEd25519SessionID(const pk: TSessionPK): string;
begin
  result := '05' + LowerCase(BytesToHex(@pk[0], 32));
end;

function GetX25519DerivedEd25519SessionID(const xpk: TSessionXPK): string;
var
  DerivedEdPK: array[0..31] of byte;
begin
  session_xed25519_pubkey(@DerivedEdPK[0], @xpk[0]);
  result := '05' + LowerCase(BytesToHex(@DerivedEdPK[0], 32));
end;

function BytesToHex(const Bytes: pointer; Len: Integer): string;
var
  I: Integer;
  P: PByte;
begin
  Result := '';
  P := PByte(Bytes);
  for I := 0 to Len - 1 do Result := Result + IntToHex(P[I], 2);
end;

procedure HexToBytes(const Hex: string; Buf: pointer);
var I, ValCode: Integer; ByteVal: Byte; P: PByte;
begin
  if length(Hex) = 0 then exit;
  P := PByte(Buf);
  for I := 0 to (Length(Hex) div 2) - 1 do
  begin
    Val('$' + Copy(Hex, (I * 2) + 1, 2), ByteVal, ValCode);
    if ValCode = 0 then P[I] := ByteVal else P[I] := 0;
  end;
end;

procedure DeriveKeyPair(const seed: TSessionSeed; out pk: TSessionPK; out sk: TSessionSK);
begin
  sodium_init();
  if session_ed25519_key_pair_seed(@seed[0], @pk[0], @sk[0]) = 0 then
    raise Exception.Create('Failed to derive key pair from seed');
end;

procedure DeriveKeyPair16(const seed: array of byte; out pk: TSessionPK; out sk: TSessionSK);
var
  I: Integer;
  Seed32: TSessionSeed;
begin
  sodium_init();
  FillChar(Seed32[0], 32, 0);
  for I := 0 to 15 do
    if I <= High(seed) then Seed32[I] := seed[I];
  if session_ed25519_key_pair_seed(@Seed32[0], @pk[0], @sk[0]) = 0 then
    raise Exception.Create('Failed to derive key pair from 16-byte seed');
end;

procedure DeriveX25519(var Identity: TSessionIdentity);
var
  I: Integer;
  Seed32: TSessionSeed;
begin
  sodium_init();
  crypto_sign_ed25519_pk_to_curve25519(@Identity.X25519PK[0], @Identity.Ed25519PK[0]);
  crypto_sign_ed25519_sk_to_curve25519(@Identity.X25519SK[0], @Identity.Ed25519SK[0]);
  FillChar(Seed32[0], 32, 0);
  for I := 0 to 15 do
    Seed32[I] := Identity.Seed[I];
  session_ed25519_pro_privkey_for_ed25519_seed(@Seed32[0], @Identity.ProSK[0]);
  
  { Derive Profile Key: blake2b(seed + "Profile Key") }
  FillChar(Identity.ProfileKey[0], 32, 0);
  session_hash(32, @Identity.Seed[0], 16, PByte(PChar('Profile Key')), 11, @Identity.ProfileKey[0]);
end;

procedure GenerateNewIdentity(out Identity: TSessionIdentity);
var
  First16: array[0..15] of byte;
  I: Integer;
begin
  Identity.Seed := GenerateSeed;
  for I := 0 to 15 do First16[I] := Identity.Seed[I];
  DeriveKeyPair16(First16, Identity.Ed25519PK, Identity.Ed25519SK);
  DeriveX25519(Identity);
  Identity.SessionID := GetSessionID(Identity.X25519PK);
end;

function LoadIdentity(const SeedPath: string; out Identity: TSessionIdentity): Boolean;
var
  Stream: TFileStream;
  First16: array[0..15] of byte;
  I: Integer;
begin
  Result := False;
  if not FileExists(SeedPath) then Exit;
  Stream := TFileStream.Create(SeedPath, fmOpenRead or fmShareDenyWrite);
  try
    if Stream.Size = 32 then
    begin
      Stream.Read(Identity.Seed[0], 32);
      for I := 0 to 15 do First16[I] := Identity.Seed[I];
      DeriveKeyPair16(First16, Identity.Ed25519PK, Identity.Ed25519SK);
      DeriveX25519(Identity);
      Identity.SessionID := GetSessionID(Identity.X25519PK);
      Result := True;
    end;
  finally
    Stream.Free;
  end;
end;

function SaveIdentity(const SeedPath: string; const Identity: TSessionIdentity): Boolean;
var Stream: TFileStream;
begin
  Result := False;
  ForceDirectories(ExtractFilePath(SeedPath));
  Stream := TFileStream.Create(SeedPath, fmCreate);
  try
    Stream.Write(Identity.Seed[0], 32);
    Result := True;
  finally
    Stream.Free;
  end;
end;

function SignData(const sk: TSessionSK; const Data: string): string;
var
  SigBytes: array[0..63] of byte;
  DataBytes: TBytes;
begin
  DataBytes := TEncoding.UTF8.GetBytes(Data);
  if session_ed25519_sign(@sk[0], @DataBytes[0], Length(DataBytes), @SigBytes[0]) = 0 then
    raise Exception.Create('Signing failed');
  Result := LowerCase(BytesToHex(@SigBytes[0], 64));
end;

procedure WriteVarint(var Dest: TBytes; Value: QWord);
begin
  repeat
    SetLength(Dest, Length(Dest) + 1);
    Dest[High(Dest)] := Value and $7F;
    Value := Value shr 7;
    if Value <> 0 then
      Dest[High(Dest)] := Dest[High(Dest)] or $80;
  until Value = 0;
end;

function EncodeContent(const Body: string; Timestamp: QWord; const DisplayName: string; const ProfileKey: TSessionPK; const ProfilePicURL: string = ''; const Attachments: TAttachmentArray = nil): TBytes;
var
  DataMsg, BodyBytes, ProfileBytes, AtchMsg, AtchBytes: TBytes;
  ResolvedDisplayName, ResolvedProfilePicURL: string;
  i: integer;
begin
  DataMsg := nil;
  
  { DataMessage Field 1: body }
  BodyBytes := TEncoding.UTF8.GetBytes(Body);
  if Length(BodyBytes) > 0 then
  begin
    SetLength(DataMsg, Length(DataMsg) + 1);
    DataMsg[High(DataMsg)] := $0A;
    WriteVarint(DataMsg, Length(BodyBytes));
    SetLength(DataMsg, Length(DataMsg) + Length(BodyBytes));
    Move(BodyBytes[0], DataMsg[Length(DataMsg) - Length(BodyBytes)], Length(BodyBytes));
  end;
  
  { DataMessage Field 2: repeated AttachmentPointer }
  for i := 0 to High(Attachments) do
  begin
    AtchMsg := nil;
    { AttachmentPointer Tag 1: deprecated_id (fixed64) - use random 64-bit value }
    SetLength(AtchMsg, Length(AtchMsg) + 9);
    AtchMsg[Length(AtchMsg)-9] := $09; // Tag 1, Type 1 (fixed64)
    randombytes_buf(@AtchMsg[Length(AtchMsg)-8], 8); 

    { AttachmentPointer Tag 3: key (bytes) }
    if Length(Attachments[i].Key) > 0 then
    begin
      SetLength(AtchMsg, Length(AtchMsg) + 1);
      AtchMsg[High(AtchMsg)] := $1A;
      WriteVarint(AtchMsg, Length(Attachments[i].Key));
      SetLength(AtchMsg, Length(AtchMsg) + Length(Attachments[i].Key));
      Move(Attachments[i].Key[0], AtchMsg[Length(AtchMsg) - Length(Attachments[i].Key)], Length(Attachments[i].Key));
    end;

    { AttachmentPointer Tag 4: size (uint32) }
    if Attachments[i].Size > 0 then
    begin
      SetLength(AtchMsg, Length(AtchMsg) + 1);
      AtchMsg[High(AtchMsg)] := $20; // Tag 4, Type 0
      WriteVarint(AtchMsg, Attachments[i].Size);
    end;

    { AttachmentPointer Tag 6: digest (bytes) }
    if Length(Attachments[i].Digest) > 0 then
    begin
      SetLength(AtchMsg, Length(AtchMsg) + 1);
      AtchMsg[High(AtchMsg)] := $32; // Tag 6, Type 2
      WriteVarint(AtchMsg, Length(Attachments[i].Digest));
      SetLength(AtchMsg, Length(AtchMsg) + Length(Attachments[i].Digest));
      Move(Attachments[i].Digest[0], AtchMsg[Length(AtchMsg) - Length(Attachments[i].Digest)], Length(Attachments[i].Digest));
    end;

    { AttachmentPointer Tag 7: fileName (string) }

    { AttachmentPointer Tag 101: url (string) }
    if Attachments[i].URL <> '' then
    begin
      AtchBytes := TEncoding.UTF8.GetBytes(Attachments[i].URL);
      SetLength(AtchMsg, Length(AtchMsg) + 2);
      AtchMsg[Length(AtchMsg)-2] := $AA;
      AtchMsg[Length(AtchMsg)-1] := $06; // Tag 101, Type 2
      WriteVarint(AtchMsg, Length(AtchBytes));
      SetLength(AtchMsg, Length(AtchMsg) + Length(AtchBytes));
      Move(AtchBytes[0], AtchMsg[Length(AtchMsg) - Length(AtchBytes)], Length(AtchBytes));
    end;

    { Add AttachmentPointer to DataMessage }
    SetLength(DataMsg, Length(DataMsg) + 1);
    DataMsg[High(DataMsg)] := $12; // Tag 2, Type 2
    WriteVarint(DataMsg, Length(AtchMsg));
    SetLength(DataMsg, Length(DataMsg) + Length(AtchMsg));
    Move(AtchMsg[0], DataMsg[Length(DataMsg) - Length(AtchMsg)], Length(AtchMsg));
  end;

  { DataMessage Field 6: profileKey }
  SetLength(DataMsg, Length(DataMsg) + 1);
  DataMsg[High(DataMsg)] := $32;
  WriteVarint(DataMsg, 32);
  SetLength(DataMsg, Length(DataMsg) + 32);
  Move(ProfileKey[0], DataMsg[Length(DataMsg) - 32], 32);

  { DataMessage Field 101: profile (LokiProfile) }
  if DisplayName <> '' then ResolvedDisplayName := DisplayName else ResolvedDisplayName := 'PrivateScout';
  ProfileBytes := nil;
  { LokiProfile Field 1: displayName }
  SetLength(ProfileBytes, Length(ProfileBytes) + 1);
  ProfileBytes[High(ProfileBytes)] := $0A;
  WriteVarint(ProfileBytes, Length(ResolvedDisplayName));
  SetLength(ProfileBytes, Length(ProfileBytes) + Length(ResolvedDisplayName));
  Move(ResolvedDisplayName[1], ProfileBytes[Length(ProfileBytes) - Length(ResolvedDisplayName)], Length(ResolvedDisplayName));
  
  { LokiProfile Field 2: profilePicture (URL) }
  if ProfilePicURL <> '' then
  begin
    ResolvedProfilePicURL := ProfilePicURL;
    if Pos('#', ResolvedProfilePicURL) > 0 then
      ResolvedProfilePicURL := Copy(ResolvedProfilePicURL, 1, Pos('#', ResolvedProfilePicURL) - 1);
    ResolvedProfilePicURL := ResolvedProfilePicURL + '#p=b8eef9821445ae16e2e97ef8aa6fe782fd11ad5253cd6723b281341dba22e371';
    SetLength(ProfileBytes, Length(ProfileBytes) + 1);
    ProfileBytes[High(ProfileBytes)] := $12;
    WriteVarint(ProfileBytes, Length(ResolvedProfilePicURL));
    SetLength(ProfileBytes, Length(ProfileBytes) + Length(ResolvedProfilePicURL));
    Move(ResolvedProfilePicURL[1], ProfileBytes[Length(ProfileBytes) - Length(ResolvedProfilePicURL)], Length(ResolvedProfilePicURL));
  end;

  { LokiProfile Field 3: lastProfileUpdateSeconds }
  SetLength(ProfileBytes, Length(ProfileBytes) + 1);
  ProfileBytes[High(ProfileBytes)] := $18;
  WriteVarint(ProfileBytes, Timestamp div 1000);

  SetLength(DataMsg, Length(DataMsg) + 2);
  DataMsg[Length(DataMsg) - 2] := $AA;
  DataMsg[Length(DataMsg) - 1] := $06; // Tag 101
  WriteVarint(DataMsg, Length(ProfileBytes));
  if Length(ProfileBytes) > 0 then
  begin
    SetLength(DataMsg, Length(DataMsg) + Length(ProfileBytes));
    Move(ProfileBytes[0], DataMsg[Length(DataMsg) - Length(ProfileBytes)], Length(ProfileBytes));
  end;

  { Content wrap: Field 1: dataMessage }
  Result := nil;
  SetLength(Result, Length(Result) + 1);
  Result[High(Result)] := $0A;
  WriteVarint(Result, Length(DataMsg));
  if Length(DataMsg) > 0 then
  begin
    SetLength(Result, Length(Result) + Length(DataMsg));
    Move(DataMsg[0], Result[Length(Result) - Length(DataMsg)], Length(DataMsg));
  end;

  { Content Field 15: sigTimestamp }
  SetLength(Result, Length(Result) + 1);
  Result[High(Result)] := $78;
  WriteVarint(Result, Timestamp);
end;

function SignDataB64(const sk: TSessionSK; const Data: string): string;
var
  SigBytes: array[0..63] of byte;
  DataBytes: TBytes;
  SigStr: string;
begin
  DataBytes := TEncoding.UTF8.GetBytes(Data);
  if session_ed25519_sign(@sk[0], @DataBytes[0], Length(DataBytes), @SigBytes[0]) = 0 then
    raise Exception.Create('Signing failed');
  SetLength(SigStr, 64);
  Move(SigBytes[0], SigStr[1], 64);
  Result := EncodeStringBase64(SigStr);
end;

function SignDataB64_X25519(const xsk: TSessionXSK; const Data: string): string;
var
  SigBytes: array[0..63] of byte;
  DataBytes: TBytes;
  SigStr: string;
begin
  DataBytes := TEncoding.UTF8.GetBytes(Data);
  if not session_xed25519_sign(@SigBytes[0], @xsk[0], @DataBytes[0], Length(DataBytes)) then
    raise Exception.Create('XEd25519 signing failed');
  SetLength(SigStr, 64);
  Move(SigBytes[0], SigStr[1], 64);
  Result := EncodeStringBase64(SigStr);
end;

function EncryptAESGCM(const Plaintext: TBytes; const Key: TBytes; out Ciphertext: TBytes): Boolean;
var ctx: pointer; iv: array[0..11] of byte; tag: array[0..15] of byte; outlen, final_len: integer;
begin
  Result := False; if (Length(Key) <> 32) then Exit;
  randombytes_buf(@iv[0], 12);
  SetLength(Ciphertext, 12 + Length(Plaintext) + 16);
  Move(iv[0], Ciphertext[0], 12);
  ctx := EVP_CIPHER_CTX_new();
  try
    if EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil) <> 1 then Exit;
    if EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nil) <> 1 then Exit;
    if EVP_EncryptInit_ex(ctx, nil, nil, @Key[0], @iv[0]) <> 1 then Exit;
    if EVP_EncryptUpdate(ctx, @Ciphertext[12], @outlen, @Plaintext[0], Length(Plaintext)) <> 1 then Exit;
    if EVP_EncryptFinal_ex(ctx, @Ciphertext[12 + outlen], @final_len) <> 1 then Exit;
    if EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, @tag[0]) <> 1 then Exit;
    Move(tag[0], Ciphertext[12 + outlen + final_len], 16);
    Result := True;
  finally EVP_CIPHER_CTX_free(ctx); end;
end;

function EncryptMessage(const Plaintext: string; const RecipientSessionID: string; const Identity: TSessionIdentity; const DisplayName: string; const ProfilePicURL: string = ''; const ProfileKeyHex: string = ''; const Attachments: TAttachmentArray = nil): string;
var
  RecipientBytes33: Tbytes33;
  Content: TBytes; EncRes: Tsession_protocol_encoded_for_destination; Timestamp: QWord;
  ErrBuf: array[0..255] of char; ActiveProfileKey: TSessionPK;
begin
  Result := '';
  if (Length(RecipientSessionID) < 66) or (Copy(RecipientSessionID, 1, 2) <> '05') then Exit;
  sodium_init();
  
  { Standard Session IDs (05...) already contain the X25519 public key.
    We just need to pass it to libsession-util. }
  RecipientBytes33.data[0] := $05;
  HexToBytes(Copy(RecipientSessionID, 3, 64), @RecipientBytes33.data[1]);
  
  Timestamp := Int64(DateTimeToUnix(LocalTimeToUniversal(Now))) * 1000;
  if ProfileKeyHex <> '' then HexToBytes(ProfileKeyHex, @ActiveProfileKey[0])
  else Move(Identity.ProfileKey[0], ActiveProfileKey[0], 32);
  Content := EncodeContent(Plaintext, Timestamp, DisplayName, ActiveProfileKey, ProfilePicURL, Attachments);
  EncRes := session_protocol_encode_for_1o1(@Content[0], Length(Content), @Identity.Ed25519SK[0], 64, Timestamp, @RecipientBytes33, nil, 0, @ErrBuf[0], 255);
  if EncRes.success then begin
    if (EncRes.ciphertext.size > 0) and (EncRes.ciphertext.data <> nil) then begin
      SetLength(Result, EncRes.ciphertext.size);
      Move(EncRes.ciphertext.data^, Result[1], EncRes.ciphertext.size);
    end;
    session_protocol_encode_for_destination_free(@EncRes);
  end;
end;

function DecryptedAttachmentBody(const Data: TBytes; const Key: TBytes; var Output: TBytes): Boolean;
var outlen: csize_t; err: array[0..255] of char;
begin
  Result := False; if (Length(Data) = 0) or (Length(Key) <> 32) then Exit;
  outlen := session_attachment_decrypted_max_size(Length(Data));
  SetLength(Output, outlen);
  Result := session_attachment_decrypt(@Data[0], Length(Data), @Key[0], @Output[0], @outlen, @err[0]);
  if Result then SetLength(Output, outlen);
end;

function ReadVarint(const Data: PByte; var Pos: Integer; MaxPos: Integer): QWord;
var Shift: Integer; B: Byte;
begin
  Result := 0; Shift := 0;
  while Pos < MaxPos do begin
    B := Data[Pos]; Inc(Pos); Result := Result or (QWord(B and $7F) shl Shift);
    if (B and $80) = 0 then Break; Inc(Shift, 7);
  end;
end;

type
  TDecodeContext = (ctxMain, ctxDataMsg, ctxLokiProfile, ctxAttachment);

function DecodeContentRecursive(const ContentPtr: PByte; ContentLen: Integer; var Msg: TDecryptedMessage; Context: TDecodeContext; Verbose: Boolean): Boolean;
var Pos: Integer; Tag, Len: QWord; AtchIdx: Integer;
begin
  Result := False; Pos := 0;
  while Pos < ContentLen do begin
    Tag := ReadVarint(ContentPtr, Pos, ContentLen);
    if Verbose then writeln(StdErr, 'DEBUG: DecodeContentRecursive - Tag: ', Tag >> 3, ' Type: ', Tag and 7, ' Context: ', Context);
    if (Tag = 0) then Break;
    if (Tag and 7) = 2 then begin
      Len := ReadVarint(ContentPtr, Pos, ContentLen);
      if Pos + Integer(Len) > ContentLen then Break;
      case (Tag >> 3) of
        1: if (Context = ctxMain) and (Len > 0) and (ContentPtr[Pos] = $0A) then DecodeContentRecursive(@ContentPtr[Pos], Len, Msg, ctxDataMsg, Verbose)
           else if (Context = ctxDataMsg) then begin SetLength(Msg.Body, Len); if Len > 0 then Move(ContentPtr[Pos], Msg.Body[1], Len); end
           else if (Context = ctxLokiProfile) then begin SetLength(Msg.DisplayName, Len); if Len > 0 then Move(ContentPtr[Pos], Msg.DisplayName[1], Len); end;
        2: if Context = ctxDataMsg then begin SetLength(Msg.Attachments, Length(Msg.Attachments) + 1); FillChar(Msg.Attachments[High(Msg.Attachments)], SizeOf(TAttachment), 0); DecodeContentRecursive(@ContentPtr[Pos], Len, Msg, ctxAttachment, Verbose); end;
        3: if Context = ctxAttachment then begin AtchIdx := High(Msg.Attachments); SetLength(Msg.Attachments[AtchIdx].Key, Len); if Len > 0 then Move(ContentPtr[Pos], Msg.Attachments[AtchIdx].Key[0], Len); end;
        4: if Context = ctxAttachment then begin AtchIdx := High(Msg.Attachments); Msg.Attachments[AtchIdx].Size := ReadVarint(@ContentPtr[Pos], Pos, Pos + Integer(Len)); end;
        6: if Context = ctxAttachment then begin AtchIdx := High(Msg.Attachments); SetLength(Msg.Attachments[AtchIdx].Digest, Len); if Len > 0 then Move(ContentPtr[Pos], Msg.Attachments[AtchIdx].Digest[0], Len); end;
        7: if Context = ctxAttachment then begin AtchIdx := High(Msg.Attachments); SetLength(Msg.Attachments[AtchIdx].FileName, Len); if Len > 0 then Move(ContentPtr[Pos], Msg.Attachments[AtchIdx].FileName[1], Len); end;
        101: if Context = ctxDataMsg then DecodeContentRecursive(@ContentPtr[Pos], Len, Msg, ctxLokiProfile, Verbose)
             else if Context = ctxAttachment then begin AtchIdx := High(Msg.Attachments); SetLength(Msg.Attachments[AtchIdx].URL, Len); if Len > 0 then Move(ContentPtr[Pos], Msg.Attachments[AtchIdx].URL[1], Len); end;
        10: if Context = ctxMain then Msg.Body := '[Message Request Accepted]';
      end;
      Inc(Pos, Len);
    end else if (Tag and 7) = 0 then begin
      Len := ReadVarint(ContentPtr, Pos, ContentLen);
      if (Context = ctxAttachment) and ((Tag >> 3) = 4) then Msg.Attachments[High(Msg.Attachments)].Size := Len;
    end else if (Tag and 7) = 1 then Inc(Pos, 8) else if (Tag and 7) = 5 then Inc(Pos, 4) else Break;
    Result := True;
  end;
end;

function DecodeContent(const ContentPtr: PByte; ContentLen: Integer; Verbose: Boolean): TDecryptedMessage;
begin
  Result.Body := ''; Result.DisplayName := ''; Result.ProfilePicURL := ''; SetLength(Result.Attachments, 0);
  if not DecodeContentRecursive(ContentPtr, ContentLen, Result, ctxMain, Verbose) then Result.Body := '[Unrecognized Content]';
end;

function DecryptMessage(const EncryptedBytes: TBytes; const Identity: TSessionIdentity; Verbose: Boolean = False): TDecryptedMessage;
var
  DecodeKeys: Tsession_protocol_decode_envelope_keys; DecRes: Tsession_protocol_decoded_envelope;
  SKSpan: array[0..1] of Tspan_u8; BackendPK: array[0..31] of byte; ErrBuf: array[0..255] of char;
  PlaintextPtr: PByte; PlaintextLen: csize_t; SIDBuf: array[0..67] of char; Decoded: TDecryptedMessage;
  SenderXPK: array[0..31] of byte;
begin
  Result.Body := '[Encrypted Message]'; Result.Sender := 'Unknown'; Result.DisplayName := ''; Result.ProfilePicURL := ''; SetLength(Result.Attachments, 0); Result.Timestamp := 0;
  if Length(EncryptedBytes) = 0 then Exit;
  SKSpan[0].data := @Identity.Ed25519SK[0]; SKSpan[0].size := 64; SKSpan[1].data := @Identity.X25519SK[0]; SKSpan[1].size := 32;
  DecodeKeys.group_ed25519_pubkey.data := nil; DecodeKeys.group_ed25519_pubkey.size := 0; DecodeKeys.decrypt_keys := @SKSpan[0]; DecodeKeys.decrypt_keys_len := 2;
  FillChar(BackendPK, 32, 0); FillChar(ErrBuf, 256, 0);
  DecRes := session_protocol_decode_envelope(@DecodeKeys, @EncryptedBytes[0], Length(EncryptedBytes), @BackendPK[0], 32, @ErrBuf[0], 255);
  if DecRes.success then begin
    if Verbose then writeln(StdErr, 'DEBUG: DecryptMessage - session_protocol_decode_envelope success');
    if (DecRes.content_plaintext.size > 0) and (DecRes.content_plaintext.data <> nil) then begin
      Decoded := DecodeContent(DecRes.content_plaintext.data, DecRes.content_plaintext.size, Verbose);
      Result.Body := Decoded.Body; Result.DisplayName := Decoded.DisplayName; Result.ProfilePicURL := Decoded.ProfilePicURL; Result.Attachments := Decoded.Attachments;
    end;
    Result.Timestamp := DecRes.envelope.timestamp_ms; 
    
    { Convert Sender Ed25519 PK to X25519 PK to form the standard Session ID }
    crypto_sign_ed25519_pk_to_curve25519(@SenderXPK[0], @DecRes.sender_ed25519_pubkey[0]);
    Result.Sender := GetSessionID(SenderXPK); 
    
    session_protocol_decode_envelope_free(@DecRes);
  end else begin
    if Verbose then writeln(StdErr, 'DEBUG: DecryptMessage - session_protocol_decode_envelope failed: ', StrPas(@ErrBuf[0]));
    FillChar(SIDBuf, 68, 0);
    if session_decrypt_incoming(@EncryptedBytes[0], Length(EncryptedBytes), @Identity.Ed25519SK[0], @SIDBuf[0], @PlaintextPtr, @PlaintextLen) then
    begin
      if Verbose then writeln(StdErr, 'DEBUG: DecryptMessage - session_decrypt_incoming success (Ed25519)');
      Result.Sender := StrPas(@SIDBuf[0]); Decoded := DecodeContent(PlaintextPtr, PlaintextLen, Verbose);
      Result.Body := Decoded.Body; Result.DisplayName := Decoded.DisplayName; Result.ProfilePicURL := Decoded.ProfilePicURL; Result.Attachments := Decoded.Attachments;
      if PlaintextPtr <> nil then libsession.free(PlaintextPtr);
    end else begin
      if Verbose then writeln(StdErr, 'DEBUG: DecryptMessage - Ed25519 failed, trying X25519...');
      { Session messages to self (X25519 namespace) use X25519 key }
      if session_decrypt_incoming(@EncryptedBytes[0], Length(EncryptedBytes), @Identity.X25519SK[0], @SIDBuf[0], @PlaintextPtr, @PlaintextLen) then
      begin
        if Verbose then writeln(StdErr, 'DEBUG: DecryptMessage - session_decrypt_incoming success (X25519)');
        Result.Sender := StrPas(@SIDBuf[0]); Decoded := DecodeContent(PlaintextPtr, PlaintextLen, Verbose);
        Result.Body := Decoded.Body; Result.DisplayName := Decoded.DisplayName; Result.ProfilePicURL := Decoded.ProfilePicURL; Result.Attachments := Decoded.Attachments;
        if PlaintextPtr <> nil then libsession.free(PlaintextPtr);
      end else begin
        if Verbose then writeln(StdErr, 'DEBUG: DecryptMessage - X25519 failed, trying Ed25519-as-X25519 fallback...');
        { Final fallback for some Note to Self implementations }
        if session_decrypt_incoming(@EncryptedBytes[0], Length(EncryptedBytes), @Identity.Ed25519SK[0], @SIDBuf[0], @PlaintextPtr, @PlaintextLen) then
        begin
          if Verbose then writeln(StdErr, 'DEBUG: DecryptMessage - session_decrypt_incoming success (Fallback)');
          Result.Sender := StrPas(@SIDBuf[0]); Decoded := DecodeContent(PlaintextPtr, PlaintextLen, Verbose);
          Result.Body := Decoded.Body; Result.DisplayName := Decoded.DisplayName; Result.ProfilePicURL := Decoded.ProfilePicURL; Result.Attachments := Decoded.Attachments;
          if PlaintextPtr <> nil then libsession.free(PlaintextPtr);
        end else if Verbose then writeln(StdErr, 'DEBUG: DecryptMessage - all decryption failed');
      end;
    end;

  end;
end;

end.
