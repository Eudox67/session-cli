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

program derive_test;
uses sessioncrypto, SysUtils;
var
  seed: TSessionSeed;
  pk: TSessionPK;
  sk: TSessionSK;
  identity: TSessionIdentity;
begin
  HexToBytes('7E312D4E1CDE75A29BB52B88DD22F974A8F13B21566263583A39F98AD2BC2258', seed);
  DeriveKeyPair(seed, pk, sk);
  identity.Seed := seed;
  identity.Ed25519PK := pk;
  identity.Ed25519SK := sk;
  DeriveX25519(identity);
  writeln('Seed: 7E31...2258');
  writeln('Ed25519 PK: ', GetSessionID(identity.Ed25519PK));
  writeln('X25519 PK (Account ID): ', GetSessionID(identity.X25519PK));
end.
