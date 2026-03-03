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

unit libsession;

{$mode objfpc}{$H+}

interface

uses
  ctypes;

const
  LIB_SESSION_UTIL = 'libsession-util.so';
  LIB_SESSION_CRYPTO = 'libsession-crypto.so';
  LIB_SESSION_ONIONREQ = 'libsession-onionreq.so';
  LIB_SESSION_CONFIG = 'libsession-config.so';

type
  Punsigned_char = ^cuchar;
  PPunsigned_char = ^Punsigned_char;

  Pnetwork_object = pointer;
  PPnetwork_object = ^Pnetwork_object;

  Tnetwork_service_node = record
    ip: array[0..3] of byte;
    quic_port: uint16;
    ed25519_pubkey_hex: array[0..64] of char;
  end;
  Pnetwork_service_node = ^Tnetwork_service_node;

  Tnetwork_get_swarm_callback = procedure(nodes: Pnetwork_service_node; nodes_len: csize_t; ctx: pointer); cdecl;
  Tnetwork_onion_response_callback = procedure(
    success: boolean; timeout: boolean; status_code: int16;
    headers: PPchar; header_values: PPchar; headers_size: csize_t;
    response: PChar; response_size: csize_t; ctx: pointer); cdecl;

  Pconfig_object = pointer;
  PPconfig_object = ^Pconfig_object;

  seqno_t = qword;

  Tspan_u8 = record
    data: PByte;
    size: csize_t;
  end;

  Tbytes33 = record
    data: array[0..32] of byte;
  end;
  Pbytes33 = ^Tbytes33;

  Tsession_protocol_encoded_for_destination = record
    success: boolean;
    ciphertext: Tspan_u8;
    error_len_incl_null_terminator: csize_t;
  end;
  Psession_protocol_encoded_for_destination = ^Tsession_protocol_encoded_for_destination;

  Tsession_protocol_decode_envelope_keys = record
    group_ed25519_pubkey: Tspan_u8;
    decrypt_keys: ^Tspan_u8;
    decrypt_keys_len: csize_t;
  end;
  Psession_protocol_decode_envelope_keys = ^Tsession_protocol_decode_envelope_keys;

  Tsession_protocol_pro_message_bitset = record
    data: uint64;
  end;

  Tsession_protocol_pro_profile_bitset = record
    data: uint64;
  end;

  Tsession_protocol_pro_proof = record
    version: uint8;
    gen_index_hash: array[0..31] of byte;
    rotating_pubkey: array[0..31] of byte;
    expiry_unix_ts_ms: uint64;
    sig: array[0..63] of byte;
  end;

  Tsession_protocol_decoded_pro = record
    status: integer;
    proof: Tsession_protocol_pro_proof;
    msg_bitset: Tsession_protocol_pro_message_bitset;
    profile_bitset: Tsession_protocol_pro_profile_bitset;
  end;

  Tsession_protocol_envelope = record
    flags: uint32;
    timestamp_ms: uint64;
    source: array[0..32] of byte;
    source_device: uint32;
    server_timestamp: uint64;
    pro_sig: array[0..63] of byte;
  end;

  Tsession_protocol_decoded_envelope = record
    success: boolean;
    envelope: Tsession_protocol_envelope;
    content_plaintext: Tspan_u8;
    sender_ed25519_pubkey: array[0..31] of byte;
    sender_x25519_pubkey: array[0..31] of byte;
    pro: Tsession_protocol_decoded_pro;
    error_len_incl_null_terminator: csize_t;
  end;
  Psession_protocol_decoded_envelope = ^Tsession_protocol_decoded_envelope;

  Tconfig_push_data = record
    seqno: seqno_t;
    config: PPunsigned_char;
    config_lens: pcsize_t;
    n_configs: csize_t;
    obsolete: PPchar;
    obsolete_len: csize_t;
  end;
  Pconfig_push_data = ^Tconfig_push_data;

  Tattachment_domain = (ATTACHMENT_DOMAIN_ATTACHMENT = 0, ATTACHMENT_DOMAIN_PROFILE_PIC = 1);

  Tencrypt_type = (ENCRYPT_TYPE_AES_GCM = 0, ENCRYPT_TYPE_X_CHA_CHA_20 = 1);
  
  Tonion_request_builder = record
    internals: pointer;
    enc_type: Tencrypt_type;
  end;
  Ponion_request_builder = ^Tonion_request_builder;
  PPonion_request_builder = ^Ponion_request_builder;

  Tcontacts_contact = record
    session_id: array[0..66] of char;
    name: array[0..100] of char;
    nickname: array[0..100] of char;
  end;
  Pcontacts_contact = ^Tcontacts_contact;

  Tcontacts_iterator = record
    _internals: pointer;
  end;
  Pcontacts_iterator = ^Tcontacts_iterator;

  Tuser_profile_pic = record
    url: array[0..223] of char;
    key: array[0..31] of byte;
  end;

// Crypto functions
function sodium_init: cint; cdecl; external LIB_SESSION_CRYPTO;
procedure randombytes_buf(buf: pointer; size: csize_t); cdecl; external LIB_SESSION_CRYPTO;
function session_ed25519_key_pair_seed(seed: pointer; pk: pointer; sk: pointer): cint; cdecl; external LIB_SESSION_CRYPTO;
function crypto_sign_ed25519_pk_to_curve25519(x_pk_out: pointer; ed_pk_in: pointer): cint; cdecl; external LIB_SESSION_CRYPTO name 'crypto_sign_ed25519_pk_to_curve25519';
function crypto_sign_ed25519_sk_to_curve25519(x_sk_out: pointer; ed_sk_in: pointer): cint; cdecl; external LIB_SESSION_CRYPTO name 'crypto_sign_ed25519_sk_to_curve25519';
function crypto_hash_sha256(&out: PByte; &in: PByte; inlen: culonglong): longint; cdecl; external LIB_SESSION_CRYPTO;
function session_to_curve25519_pubkey(ed25519_pubkey: pointer; curve25519_pk_out: pointer): boolean; cdecl; external LIB_SESSION_CRYPTO;
function session_to_curve25519_seckey(ed25519_seckey: pointer; curve25519_sk_out: pointer): boolean; cdecl; external LIB_SESSION_CRYPTO;
function session_ed25519_sign(sk: pointer; msg: pointer; msg_len: csize_t; sig_out: pointer): cint; cdecl; external LIB_SESSION_CRYPTO;
function session_xed25519_sign(sig: PByte; curve25519_privkey: PByte; msg: PByte; msg_len: csize_t): boolean; cdecl; external LIB_SESSION_CRYPTO;
function session_xed25519_pubkey(ed25519_pubkey: PByte; curve25519_pubkey: PByte): boolean; cdecl; external LIB_SESSION_CRYPTO;
function session_ed25519_pro_privkey_for_ed25519_seed(const ed25519_seed: pointer; ed25519_sk_out: pointer): boolean; cdecl; external LIB_SESSION_CRYPTO;
function session_encrypt_for_recipient_deterministic(plaintext: pointer; plaintext_len: csize_t; sender_ed_sk: pointer; recipient_x_pk: pointer; ciphertext_out: PPunsigned_char; ciphertext_len: pcsize_t): cint; cdecl; external LIB_SESSION_CRYPTO;
function session_decrypt_incoming(ciphertext_in: pointer; ciphertext_len: csize_t; ed25519_privkey: pointer; session_id_out: PChar; plaintext_out: PPunsigned_char; plaintext_len: pcsize_t): boolean; cdecl; external LIB_SESSION_CRYPTO;

// Network functions
function network_init(network: PPnetwork_object; cache_path: PChar; use_testnet: boolean; single_path_mode: boolean; pre_build_paths: boolean; error: PChar): boolean; cdecl; external LIB_SESSION_ONIONREQ;
procedure network_free(network: Pnetwork_object); cdecl; external LIB_SESSION_ONIONREQ;
procedure network_get_swarm(network: Pnetwork_object; swarm_pubkey_hex: PChar; callback: Tnetwork_get_swarm_callback; ctx: pointer); cdecl; external LIB_SESSION_ONIONREQ;
procedure network_send_onion_request_to_snode_destination(network: Pnetwork_object; node: Tnetwork_service_node; body: PByte; body_size: csize_t; swarm_pubkey_hex: PChar; request_timeout_ms: int64; request_and_path_build_timeout_ms: int64; callback: Tnetwork_onion_response_callback; ctx: pointer); cdecl; external LIB_SESSION_ONIONREQ;

// Config Base functions
function config_needs_push(conf: Pconfig_object): boolean; cdecl; external LIB_SESSION_CONFIG;
function config_push(conf: Pconfig_object): Pconfig_push_data; cdecl; external LIB_SESSION_CONFIG;
procedure config_confirm_pushed(conf: Pconfig_object; seqno: seqno_t; msg_hashes: PPchar; hashes_len: csize_t); cdecl; external LIB_SESSION_CONFIG;
function config_dump(conf: Pconfig_object; out_data: PPunsigned_char; out_len: pcsize_t): boolean; cdecl; external LIB_SESSION_CONFIG;
function config_needs_dump(conf: Pconfig_object): boolean; cdecl; external LIB_SESSION_CONFIG;
function config_storage_namespace(conf: Pconfig_object): int16; cdecl; external LIB_SESSION_CONFIG;

// User Profile functions
function user_profile_init(conf: PPconfig_object; ed25519_secretkey: pointer; dump: PByte; dumplen: csize_t; error: PChar): cint; cdecl; external LIB_SESSION_CONFIG;
function user_profile_set_name(conf: Pconfig_object; name: PChar): cint; cdecl; external LIB_SESSION_CONFIG;
function user_profile_get_name(conf: Pconfig_object): PChar; cdecl; external LIB_SESSION_CONFIG;
function user_profile_get_pic(const conf: Pconfig_object): Tuser_profile_pic; cdecl; external LIB_SESSION_CONFIG;
function user_profile_set_pic(conf: Pconfig_object; pic: Tuser_profile_pic): cint; cdecl; external LIB_SESSION_CONFIG;
function user_profile_set_reupload_pic(conf: Pconfig_object; pic: Tuser_profile_pic): cint; cdecl; external LIB_SESSION_CONFIG;
procedure config_free(conf: Pconfig_object); cdecl; external LIB_SESSION_CONFIG;

// Session Protocol functions
function session_protocol_encode_for_1o1(plaintext: pointer; plaintext_len: csize_t; ed25519_privkey: pointer; ed25519_privkey_len: csize_t; sent_timestamp_ms: uint64; recipient_pubkey: Pbytes33; pro_rotating_ed25519_privkey: pointer; pro_rotating_ed25519_privkey_len: csize_t; error: PChar; error_len: csize_t): Tsession_protocol_encoded_for_destination; cdecl; external LIB_SESSION_CRYPTO;
procedure session_protocol_encode_for_destination_free(res: Psession_protocol_encoded_for_destination); cdecl; external LIB_SESSION_CRYPTO;
function session_protocol_decode_envelope(keys: Psession_protocol_decode_envelope_keys; envelope_plaintext: pointer; envelope_plaintext_len: csize_t; pro_backend_pubkey: pointer; pro_backend_pubkey_len: csize_t; error: PChar; error_len: csize_t): Tsession_protocol_decoded_envelope; cdecl; external LIB_SESSION_CRYPTO;
procedure session_protocol_decode_envelope_free(envelope: Psession_protocol_decoded_envelope); cdecl; external LIB_SESSION_CRYPTO;

// Attachment functions
function session_attachment_encrypted_size(plaintext_size: csize_t): csize_t; cdecl; external LIB_SESSION_CRYPTO;
function session_attachment_decrypted_max_size(encrypted_size: csize_t): csize_t; cdecl; external LIB_SESSION_CRYPTO;
procedure session_attachment_encrypt(seed: PByte; data: PByte; datalen: csize_t; domain: Tattachment_domain; key_out: PByte; &out: PByte; error: PChar); cdecl; external LIB_SESSION_CRYPTO;
function session_attachment_decrypt(data: PByte; datalen: csize_t; key: PByte; &out: PByte; outlen: pcsize_t; error: PChar): boolean; cdecl; external LIB_SESSION_CRYPTO;
function session_attachment_decrypt_alloc(data: PByte; datalen: csize_t; key: PByte; &out: PPunsigned_char; outlen: pcsize_t; error: PChar): boolean; cdecl; external LIB_SESSION_CRYPTO;
function session_hash(size: csize_t; msg_in: PByte; msg_len: csize_t; key_in: PByte; key_len: csize_t; hash_out: PByte): boolean; cdecl; external LIB_SESSION_CRYPTO;
function crypto_aead_xchacha20poly1305_ietf_decrypt(m: PByte; mlen_p: pculonglong; nsec: PByte; c: PByte; clen: culonglong; ad: PByte; adlen: culonglong; npub: PByte; k: PByte): cint; cdecl; external LIB_SESSION_CRYPTO;

const
  LIB_CRYPTO = 'libcrypto.so';

function EVP_aes_256_gcm: pointer; cdecl; external LIB_CRYPTO;
function EVP_CIPHER_CTX_new: pointer; cdecl; external LIB_CRYPTO;
procedure EVP_CIPHER_CTX_free(ctx: pointer); cdecl; external LIB_CRYPTO;
function EVP_EncryptInit_ex(ctx: pointer; const cipher: pointer; impl: pointer; const key: PByte; const iv: PByte): cint; cdecl; external LIB_CRYPTO;
function EVP_EncryptUpdate(ctx: pointer; out_: PByte; outl: pcint; const in_: PByte; inl: cint): cint; cdecl; external LIB_CRYPTO;
function EVP_EncryptFinal_ex(ctx: pointer; out_: PByte; outl: pcint): cint; cdecl; external LIB_CRYPTO;
function EVP_CIPHER_CTX_ctrl(ctx: pointer; type_: cint; arg: cint; ptr: pointer): cint; cdecl; external LIB_CRYPTO;

const
  EVP_CTRL_GCM_SET_IVLEN = $09;
  EVP_CTRL_GCM_GET_TAG = $10;

// Onion Request functions
procedure onion_request_builder_init(builder: PPonion_request_builder); cdecl; external LIB_SESSION_ONIONREQ;
procedure onion_request_builder_free(builder: Ponion_request_builder); cdecl; external LIB_SESSION_ONIONREQ;
procedure onion_request_builder_set_enc_type(builder: Ponion_request_builder; enc_type: Tencrypt_type); cdecl; external LIB_SESSION_ONIONREQ;
procedure onion_request_builder_set_snode_destination(builder: Ponion_request_builder; const ip: array of uint8; quic_port: uint16; const ed25519_pubkey: PChar); cdecl; external LIB_SESSION_ONIONREQ;
procedure onion_request_builder_set_server_destination(builder: Ponion_request_builder; const protocol, host, endpoint, method: PChar; port: uint16; const x25519_pubkey: PChar); cdecl; external LIB_SESSION_ONIONREQ;
procedure onion_request_builder_add_hop(builder: Ponion_request_builder; const ed25519_pubkey, x25519_pubkey: PChar); cdecl; external LIB_SESSION_ONIONREQ;
function onion_request_builder_build(builder: Ponion_request_builder; payload_in: PByte; payload_in_len: csize_t; payload_out: PPunsigned_char; payload_out_len: pcsize_t; final_x25519_pubkey_out: PByte; final_x25519_seckey_out: PByte): boolean; cdecl; external LIB_SESSION_ONIONREQ;

// Contacts functions
function contacts_init(conf: PPconfig_object; ed25519_secretkey: pointer; dump: PByte; dumplen: csize_t; error: PChar): cint; cdecl; external LIB_SESSION_CONFIG;
function contacts_get_or_construct(conf: Pconfig_object; contact: Pcontacts_contact; const session_id: PChar): boolean; cdecl; external LIB_SESSION_CONFIG;
function contacts_set(conf: Pconfig_object; const contact: Pcontacts_contact): boolean; cdecl; external LIB_SESSION_CONFIG;
function contacts_size(const conf: Pconfig_object): csize_t; cdecl; external LIB_SESSION_CONFIG;
function contacts_iterator_new(const conf: Pconfig_object): Pcontacts_iterator; cdecl; external LIB_SESSION_CONFIG;
procedure contacts_iterator_free(it: Pcontacts_iterator); cdecl; external LIB_SESSION_CONFIG;
function contacts_iterator_done(it: Pcontacts_iterator; contact: Pcontacts_contact): boolean; cdecl; external LIB_SESSION_CONFIG;
procedure contacts_iterator_advance(it: Pcontacts_iterator); cdecl; external LIB_SESSION_CONFIG;

procedure free(p: pointer); cdecl; external 'libc.so.6' name 'free';
function malloc(size: csize_t): pointer; cdecl; external 'libc.so.6' name 'malloc';
function strdup(s: PChar): PChar; cdecl; external 'libc.so.6' name 'strdup';

implementation

end.