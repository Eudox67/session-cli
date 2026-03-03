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

program test_seed;
uses sessioncrypto, SysUtils;
var
  FullSeed: TSessionSeed;
  First16: array[0..15] of byte;
  identity: TSessionIdentity;
  i: integer;
begin
  // Old seed user wants to use (16 bytes hex = 32 chars)
  HexToBytes('7E312D4E1CDE75A29BB52B88DD22F974', FullSeed);
  
  writeln('Input seed (16 bytes): 7E312D4E1CDE75A29BB52B88DD22F974');
  writeln('');
  
  // Test 1: Use first 16 bytes
  for i := 0 to 15 do First16[i] := FullSeed[i];
  identity.Seed := FullSeed;
  DeriveKeyPair16(First16, identity.Ed25519PK, identity.Ed25519SK);
  DeriveX25519(identity);
  writeln('Using first 16 bytes:');
  writeln('X25519: ', GetSessionID(identity.X25519PK));
  writeln('');
  
  // Test 2: Try as if 16 bytes is already the full seed (no copy needed)
  identity.Seed := FullSeed;
  DeriveKeyPair16(FullSeed, identity.Ed25519PK, identity.Ed25519SK);
  DeriveX25519(identity);
  writeln('Using as 16-byte seed directly:');
  writeln('X25519: ', GetSessionID(identity.X25519PK));
  
  writeln('');
  writeln('Expected by Session Desktop: 05dce4d029a198263f5ce68d90ec510f2e520aa529a50eb4491e82c3939620c671');
end.
