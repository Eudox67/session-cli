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

unit zmq_utils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, zmq, BaseUnix;

function zmq_send_string(socket: pointer; s: string; flags: integer = 0): integer;
function zmq_recv_string(socket: pointer): string;
function zmq_recv_stream(socket: pointer; s: TMemoryStream): integer;

function Base64EncodeBytes(const b: TBytes): string;
function Base64DecodeBytes(const s: string): TBytes;

implementation

function zmq_send_string(socket: pointer; s: string; flags: integer = 0): integer;
var 
  rc: integer;
  message: zmq_msg_t;
  err: integer;
begin
  if Length(s) = 0 then
  begin
    zmq_msg_init_size(@message, 0);
  end
  else
  begin
    zmq_msg_init_size(@message, length(s));
    move(pchar(s)^, zmq_msg_data(@message)^, length(s));
  end;

  rc := zmq_msg_send(@message, socket, flags);
  if rc = -1 then
  begin
    err := zmq_errno();
    writeln('ZMQ Send Error: ', zmq_strerror(err), ' (', err, ')');
  end;
  
  zmq_msg_close(@message);
  result := rc;
end;

function zmq_recv_string(socket: pointer): string;
var
  message: zmq_msg_t;
  size: integer;
  err: integer;
begin
  result := '';
  zmq_msg_init(@message);
  size := zmq_msg_recv(@message, socket, 0);
  
  if size = -1 then
  begin
    err := zmq_errno();
    if err <> ESysEAGAIN then
      writeln('ZMQ Recv Error: ', zmq_strerror(err), ' (', err, ')')
    else
      writeln('ZMQ Recv Timeout (EAGAIN)');
      
    zmq_msg_close(@message);
    exit;
  end;
  
  if size > 0 then
    SetString(result, PChar(zmq_msg_data(@message)), size)
  else
    result := '';
    
  zmq_msg_close(@message);
end;

function zmq_recv_stream(socket: pointer; s: TMemoryStream): integer;
var
  message: zmq_msg_t;
begin
  zmq_msg_init(@message);
  result := zmq_msg_recv(@message, socket, 0);
  if (result = -1) then exit;
  
  s.Write(zmq_msg_data(@message)^, result);
  zmq_msg_close(@message);
end;

function Base64EncodeBytes(const b: TBytes): string;
const
  B64Tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
  i, val, bits: integer;
begin
  Result := '';
  if Length(b) = 0 then exit;
  val := 0; bits := 0;
  for i := 0 to High(b) do
  begin
    val := (val shl 8) or b[i];
    bits := bits + 8;
    while bits >= 6 do
    begin
      bits := bits - 6;
      Result := Result + B64Tab[((val shr bits) and $3F) + 1];
    end;
  end;
  if bits > 0 then
    Result := Result + B64Tab[((val shl (6 - bits)) and $3F) + 1];
  while (Length(Result) mod 4) <> 0 do Result := Result + '=';
end;

function Base64DecodeBytes(const s: string): TBytes;
const
  B64Tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
  i, val, bits, p: integer;
begin
  Result := nil;
  val := 0; bits := 0;
  for i := 1 to Length(s) do
  begin
    if s[i] = '=' then Break;
    p := Pos(s[i], B64Tab);
    if p = 0 then Continue;
    val := (val shl 6) or (p - 1);
    bits := bits + 6;
    if bits >= 8 then
    begin
      bits := bits - 8;
      SetLength(Result, Length(Result) + 1);
      Result[High(Result)] := (val shr bits) and $FF;
    end;
  end;
end;

end.
