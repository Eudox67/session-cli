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

unit sessionmnemonic;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes;

function SeedToMnemonic(const SeedHex: string): string;
function MnemonicToSeed(const Mnemonic: string; out SeedHex: string): Boolean;

implementation

const
  SESSION_WORDLIST_SIZE = 1626;
  PREFIX_LEN = 3;
  // Session uses 13 words total (12 entropy + 1 checksum)
  NUM_ENTROPY_WORDS = 12; 
  NUM_TOTAL_WORDS = 13;

{$I session_wordlist.inc}

var
  SessionTruncWords: array[0..SESSION_WORDLIST_SIZE - 1] of string[PREFIX_LEN];
  SessionWordsInitialized: Boolean = False;

procedure InitSessionWords;
var
  I: Integer;
begin
  if SessionWordsInitialized then Exit;
  for I := 0 to SESSION_WORDLIST_SIZE - 1 do
    SessionTruncWords[I] := Copy(SESSION_EMBEDDED_WORDLIST[I], 1, PREFIX_LEN);
  SessionWordsInitialized := True;
end;

// CRC32 Implementation specific to the one used in buffer-crc32 (unsigned)
var
  CRC32Table: array[0..255] of Cardinal;
  CRC32TableInit: Boolean = False;

procedure InitCRC32;
var
  i, j: Integer;
  crc: Cardinal;
begin
  if CRC32TableInit then Exit;
  for i := 0 to 255 do
  begin
    crc := i;
    for j := 0 to 7 do
    begin
      if (crc and 1) <> 0 then
        crc := (crc shr 1) xor $EDB88320
      else
        crc := crc shr 1;
    end;
    CRC32Table[i] := crc;
  end;
  CRC32TableInit := True;
end;

function CalculateCRC32(const Data: string): Cardinal;
var
  i: Integer;
begin
  if not CRC32TableInit then InitCRC32;
  Result := $FFFFFFFF;
  for i := 1 to Length(Data) do
    Result := (Result shr 8) xor CRC32Table[(Result xor Byte(Data[i])) and $FF];
  Result := Result xor $FFFFFFFF; // Finalize to match unsigned
end;

// TypeScript: mn_swap_endian_4byte
function SwapEndian4Byte(const HexStr: string): string;
begin
  // Input "AABBCCDD", Output "DDCCBBAA"
  Result := Copy(HexStr, 7, 2) + Copy(HexStr, 5, 2) + 
            Copy(HexStr, 3, 2) + Copy(HexStr, 1, 2);
end;

function GetWordIndex(const TruncWord: string): Integer;
var
  I: Integer;
begin
  if not SessionWordsInitialized then InitSessionWords;
  Result := -1;
  for I := 0 to SESSION_WORDLIST_SIZE - 1 do
  begin
    if SessionTruncWords[I] = TruncWord then
    begin
      Result := I;
      Exit;
    end;
  end;
end;

function GetChecksumIndex(const Words: array of string): Integer;
var
  TrimmedWords: string;
  I: Integer;
  Chk: Cardinal;
begin
  TrimmedWords := '';
  for I := 0 to High(Words) do
  begin
    TrimmedWords := TrimmedWords + Copy(Words[I], 1, PREFIX_LEN);
  end;
  
  Chk := CalculateCRC32(TrimmedWords);
  Result := Chk mod Length(Words);
end;

function SeedToMnemonic(const SeedHex: string): string;
var
  N: Cardinal;
  StrCopy, Chunk, SwappedChunk: string;
  I: Integer;
  Val: Cardinal;
  W1, W2, W3: Cardinal;
  EntropyWords: array of string;
  ChecksumIdx: Integer;
begin
  Result := '';
  if Length(SeedHex) <> 32 then Exit('ERROR: Seed must be 32 hex chars');

  N := SESSION_WORDLIST_SIZE;
  StrCopy := LowerCase(SeedHex);
  SetLength(EntropyWords, 0);

  // mnEncode logic
  for I := 0 to 3 do // 32 chars / 8 chars per chunk = 4 chunks
  begin
    // Extract 8 hex chars (4 bytes)
    Chunk := Copy(StrCopy, (I * 8) + 1, 8);
    
    // IMPORTANT: Swap Endianness before integer conversion
    SwappedChunk := SwapEndian4Byte(Chunk);
    
    Val := StrToInt64('$' + SwappedChunk);
    
    W1 := Val mod N;
    W2 := ((Val div N) + W1) mod N;
    W3 := ((Val div (N * N)) + W2) mod N; // Math.floor(x/n)/n is integer division val / n^2
    
    SetLength(EntropyWords, Length(EntropyWords) + 3);
    EntropyWords[High(EntropyWords) - 2] := SESSION_EMBEDDED_WORDLIST[W1];
    EntropyWords[High(EntropyWords) - 1] := SESSION_EMBEDDED_WORDLIST[W2];
    EntropyWords[High(EntropyWords)]     := SESSION_EMBEDDED_WORDLIST[W3];
  end;

  // Calculate Checksum
  ChecksumIdx := GetChecksumIndex(EntropyWords);
  
  // Construct Result
  for I := 0 to High(EntropyWords) do
  begin
    if I > 0 then Result := Result + ' ';
    Result := Result + EntropyWords[I];
  end;
  
  // Append Checksum Word
  Result := Result + ' ' + EntropyWords[ChecksumIdx];
end;

function MnemonicToSeed(const Mnemonic: string; out SeedHex: string): Boolean;
var
  Words: TStringArray;
  N: Cardinal;
  I: Integer;
  W1, W2, W3: Integer;
  X: Cardinal;
  HexChunk: string;
  ChecksumWord, ExpectedChecksum: string;
  ChecksumIdx: Integer;
  EntropyOnly: array of string;
begin
  Result := False;
  SeedHex := '';
  N := SESSION_WORDLIST_SIZE;
  
  Words := Mnemonic.Split([' ']);
  
  // mnDecode validation logic
  if Length(Words) < NUM_ENTROPY_WORDS then Exit; // NotEnoughWords
  if Length(Words) > NUM_TOTAL_WORDS then Exit; // TooManyWords

  // Extract Checksum Word
  ChecksumWord := Words[High(Words)];
  SetLength(Words, Length(Words) - 1); // Remove checksum from list
  
  // Verify Checksum
  SetLength(EntropyOnly, Length(Words));
  for I := 0 to High(Words) do EntropyOnly[I] := Words[I];
  
  ChecksumIdx := GetChecksumIndex(EntropyOnly);
  ExpectedChecksum := EntropyOnly[ChecksumIdx];
  
  if Copy(ExpectedChecksum, 1, PREFIX_LEN) <> Copy(ChecksumWord, 1, PREFIX_LEN) then
    Exit; // VerificationError

  // Decode
  for I := 0 to 3 do // 4 chunks of 3 words
  begin
    // Find indices based on truncated words
    W1 := GetWordIndex(Copy(Words[I*3], 1, PREFIX_LEN));
    W2 := GetWordIndex(Copy(Words[I*3+1], 1, PREFIX_LEN));
    W3 := GetWordIndex(Copy(Words[I*3+2], 1, PREFIX_LEN));
    
    if (W1 = -1) or (W2 = -1) or (W3 = -1) then Exit; // InvalidWordsError

    // x = w1 + n * ((n - w1 + w2) % n) + n * n * ((n - w2 + w3) % n);
    X := Cardinal(W1) + 
         N * ((N - Cardinal(W1) + Cardinal(W2)) mod N) + 
         (N * N) * ((N - Cardinal(W2) + Cardinal(W3)) mod N);

    HexChunk := IntToHex(X, 8);
    SeedHex := SeedHex + SwapEndian4Byte(HexChunk);
  end;

  SeedHex := UpperCase(SeedHex);
  Result := True;
end;

initialization
  InitSessionWords;
end.
