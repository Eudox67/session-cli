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

program debug_seed;
uses sessioncrypto, SysUtils;
var
  Seed16: array[0..15] of byte;
  identity: TSessionIdentity;
  i: integer;
begin
  // This is what the config should have
  HexToBytes('7E312D4E1CDE75A29BB52B88DD22F974', Seed16);
  
  writeln('DEBUG: Seed16 bytes:');
  for i := 0 to 15 do write(IntToHex(Seed16[i], 2), ' ');
  writeln;
  
  // Use Seed16 directly for derivation
  DeriveKeyPair16(Seed16, identity.Ed25519PK, identity.Ed25519SK);
  
  writeln('Ed25519 PK: ', LowerCase(BytesToHex(identity.Ed25519PK, 32)));
  writeln('Ed25519 SK: ', LowerCase(BytesToHex(identity.Ed25519SK, 64)));
  
  DeriveX25519(identity);
  
  writeln('X25519 PK:  ', LowerCase(BytesToHex(identity.X25519PK, 32)));
  writeln('X25519 SK:  ', LowerCase(BytesToHex(identity.X25519SK, 32)));
  
  writeln('X25519 SessionID: ', GetSessionID(identity.X25519PK));
  writeln('');
  writeln('Expected:          05dce4d029a198263f5ce68d90ec510f2e520aa529a50eb4491e82c3939620c671');
end.
