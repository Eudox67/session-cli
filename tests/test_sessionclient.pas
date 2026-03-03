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

unit test_sessionclient;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpcunit, testutils, testregistry, ctypes, strutils,
  sessionclient, sessioncrypto, libsession, sessionconfig;

type
  TTestSessionClient = class(TTestCase)
  protected
    FConfig: TSessionConfig;
    FClient: TSessionClient;
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestIdentityGeneration;
    procedure TestMnemonicRoundtrip;
    procedure TestAttachmentEncryption;
    procedure TestContactManagement;
  end;

implementation

uses sessionmnemonic;

procedure TTestSessionClient.SetUp;
begin
  if FileExists('test_session.conf') then DeleteFile('test_session.conf');
  FConfig := TSessionConfig.Create;
  FConfig.ConfigPath := 'test_session.conf';
  FConfig.Load;
  FClient := TSessionClient.Create(FConfig);
end;

procedure TTestSessionClient.TearDown;
begin
  FClient.Free;
  FConfig.Free;
  if FileExists('test_session.conf') then DeleteFile('test_session.conf');
end;

procedure TTestSessionClient.TestIdentityGeneration;
begin
  FClient.EnsureIdentity;
  AssertTrue('Session ID should start with 05. Got: ' + FClient.Config.SessionID, copy(FClient.Config.SessionID, 1, 2) = '05');
  AssertEquals('Session ID length should be 66', 66, length(FClient.Config.SessionID));
end;

procedure TTestSessionClient.TestMnemonicRoundtrip;
var
  Seed, Mnemonic, Recovered: string;
  Words: TStringList;
begin
  FClient.EnsureIdentity;
  Seed := Copy(FClient.Config.SeedHex, 1, 32);
  Mnemonic := SeedToMnemonic(Seed);
  
  Words := TStringList.Create;
  try
    Words.Delimiter := ' ';
    Words.StrictDelimiter := True;
    Words.DelimitedText := Mnemonic;
    AssertEquals('Mnemonic should be 13 words. Got: ' + Mnemonic, 13, Words.Count);
  finally Words.Free; end;
  
  AssertTrue('MnemonicToSeed should succeed', MnemonicToSeed(Mnemonic, Recovered));
  AssertEquals('Recovered seed should match original', Seed, Recovered);
end;

procedure TTestSessionClient.TestAttachmentEncryption;
var
  Plaintext, Encrypted, Decrypted: TBytes;
  Key: TBytes;
  i: integer;
  Seed: TSessionSeed;
  err: array[0..255] of char;
  enc_size: csize_t;
begin
  SetLength(Plaintext, 100);
  for i := 0 to 99 do Plaintext[i] := i;
  
  FillChar(Seed[0], 32, $AA);
  enc_size := session_attachment_encrypted_size(100);
  SetLength(Encrypted, enc_size);
  SetLength(Key, 32);
  
  { Test Encrypt }
  session_attachment_encrypt(@Seed[0], @Plaintext[0], 100, ATTACHMENT_DOMAIN_ATTACHMENT, @Key[0], @Encrypted[0], @err[0]);
  AssertTrue('Encrypted data should be different from plaintext', not CompareMem(@Plaintext[0], @Encrypted[0], 100));
  
  { Test Decrypt }
  AssertTrue('Decryption should succeed', DecryptedAttachmentBody(Encrypted, Key, Decrypted));
  AssertEquals('Decrypted size should match original', 100, length(Decrypted));
  AssertTrue('Decrypted content should match original', CompareMem(@Plaintext[0], @Decrypted[0], 100));
end;

procedure TTestSessionClient.TestContactManagement;
begin
  FClient.AddContact('TestUser', '05dce4d029a198263f5ce68d90ec510f2e520aa529a50eb4491e82c3939620c671');
  AssertEquals('Contact list should have 1 entry', 1, Length(FClient.Config.Contacts));
  AssertEquals('Contact name should match', 'TestUser', FClient.Config.Contacts[0].Name);
  
  FClient.RemoveContact('TestUser');
  AssertEquals('Contact list should be empty', 0, Length(FClient.Config.Contacts));
end;

initialization
  RegisterTest(TTestSessionClient);
end.
