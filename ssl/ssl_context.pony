use "crypto"
use @SSL_CTX_new[SSLContextST](methods: SSLMethodST)
use @SSLv23_method[SSLMethodST]()
use @SSL_CTX_ctrl[I64](ctx: SSLContextST tag, cmd: I32, larg: I64, parg: Pointer[None] tag)

struct SSLContextST
struct SSLMethodST

class SSLContext
  var _ctx: SSLContextST
  var _client_verify: Bool = true
  var _server_verify: Bool = false

	new create() =>
    _ctx = @SSL_CTX_new(@SSLv23_method())
    set_options(_SslOpNoSslMask() + _SslOpNoSslV2())


  fun ref allow_tls_v1_v2(state: Bool) =>
    if not (NullablePointer[SSLContextST](_ctx).is_none()) then
      clear_options(_SslOpNoTlsV1u2())
    else
      set_options(_SslOpNoTlsV1u2())
    end


  fun ref set_options(opts: I64): I64 =>
    @SSL_CTX_ctrl(_ctx, I32(32), opts, Pointer[None]) // SSL_CTRL_OPTIONS

  fun ref clear_options(opts: I64): I64 =>
    @SSL_CTX_ctrl(_ctx, I32(77), opts, Pointer[None]) // SSL_CTRL_CLEAR_OPTIONS


primitive _SslOpNoSslV2    fun val apply(): I64 => 0x01000000 // 0 in 1.1
primitive _SslOpNoSslV3    fun val apply(): I64 => 0x02000000
primitive _SslOpNoTlsV1    fun val apply(): I64 => 0x04000000
primitive _SslOpNoTlsV1u2  fun val apply(): I64 => 0x08000000
primitive _SslOpNoTlsV1u1  fun val apply(): I64 => 0x10000000
primitive _SslOpNoTlsV1u3  fun val apply(): I64 => 0x20000000

primitive _SslOpNoDtlsV1   fun val apply(): I64 => 0x04000000
primitive _SslOpNoDtlsV1u2 fun val apply(): I64 => 0x08000000

// Defined as SSL_OP_NO_SSL_MASK in ssl.h
primitive _SslOpNoSslMask
  fun val apply(): I64 =>
    _SslOpNoSslV3() + _SslOpNoTlsV1() + _SslOpNoTlsV1u1() + _SslOpNoTlsV1u2()
      + _SslOpNoTlsV1u3()



/*
  Original Name: SSL_CTX_set_msg_callback./include/openssl/ssl.h:501
  Original Name: SSL_CTX_set_keylog_callback./include/openssl/ssl.h:509
  Original Name: SSL_CTX_get_keylog_callback./include/openssl/ssl.h:510
  Original Name: SSL_CTX_set_num_tickets./include/openssl/ssl.h:513
  Original Name: SSL_CTX_get_num_tickets./include/openssl/ssl.h:514
  Original Name: SSL_CTX_sessions./include/openssl/ssl.h:562
  Original Name: SSL_CTX_sess_set_new_cb./include/openssl/ssl.h:588
  Original Name: SSL_CTX_sess_get_new_cb./include/openssl/ssl.h:590
  Original Name: SSL_CTX_sess_set_remove_cb./include/openssl/ssl.h:592
  Original Name: SSL_CTX_sess_get_remove_cb./include/openssl/ssl.h:594
  Original Name: SSL_CTX_sess_set_get_cb./include/openssl/ssl.h:596
  Original Name: SSL_CTX_sess_get_get_cb./include/openssl/ssl.h:599
  Original Name: SSL_CTX_set_info_callback./include/openssl/ssl.h:601
  Original Name: SSL_CTX_get_info_callback./include/openssl/ssl.h:603
  Original Name: SSL_CTX_set_client_cert_cb./include/openssl/ssl.h:605
  Original Name: SSL_CTX_get_client_cert_cb./include/openssl/ssl.h:607
  Original Name: SSL_CTX_set_client_cert_engine./include/openssl/ssl.h:610
  Original Name: SSL_CTX_set_cookie_generate_cb./include/openssl/ssl.h:612
  Original Name: SSL_CTX_set_cookie_verify_cb./include/openssl/ssl.h:615
  Original Name: SSL_CTX_set_next_protos_advertised_cb./include/openssl/ssl.h:618
  Original Name: SSL_CTX_set_next_proto_select_cb./include/openssl/ssl.h:620
  Original Name: SSL_CTX_set_alpn_protos./include/openssl/ssl.h:634
  Original Name: SSL_CTX_set_alpn_select_cb./include/openssl/ssl.h:638
  Original Name: SSL_CTX_set_tlsext_use_srtp./include/openssl/srtp.h:136
  Original Name: SSL_CTX_set_post_handshake_auth./include/openssl/ssl.h:747
  Original Name: SSL_CTX_set0_chain./include/openssl/ssl.h:999
  Original Name: SSL_CTX_set1_chain./include/openssl/ssl.h:1000
  Original Name: SSL_CTX_add0_chain_cert./include/openssl/ssl.h:1001
  Original Name: SSL_CTX_add1_chain_cert./include/openssl/ssl.h:1002
  Original Name: SSL_CTX_get0_chain_certs./include/openssl/ssl.h:1003
  Original Name: SSL_CTX_clear_chain_certs./include/openssl/ssl.h:1004
  Original Name: SSL_CTX_set1_groups./include/openssl/ssl.h:1013
  Original Name: SSL_CTX_set1_groups_list./include/openssl/ssl.h:1014
  Original Name: SSL_CTX_get_min_proto_version./include/openssl/ssl.h:1019
  Original Name: SSL_CTX_get_max_proto_version./include/openssl/ssl.h:1020
  Original Name: SSL_CTX_set_min_proto_version./include/openssl/ssl.h:1021
  Original Name: SSL_CTX_set_max_proto_version./include/openssl/ssl.h:1022
  Original Name: SSL_CTX_get_ssl_method./include/openssl/ssl.h:1029
  Original Name: SSL_CTX_get_ciphers./include/openssl/ssl.h:1109
  Original Name: SSL_CTX_set_cipher_list./include/openssl/ssl.h:1110
  Original Name: SSL_CTX_set_ciphersuites./include/openssl/ssl.h:1112
  Original Name: SSL_CTX_new./include/openssl/ssl.h:1114
  Original Name: SSL_CTX_free./include/openssl/ssl.h:1115
  Original Name: SSL_CTX_up_ref./include/openssl/ssl.h:1116
  Original Name: SSL_CTX_set_timeout./include/openssl/ssl.h:1117
  Original Name: SSL_CTX_get_timeout./include/openssl/ssl.h:1118
  Original Name: SSL_CTX_get_cert_store./include/openssl/ssl.h:1119
  Original Name: SSL_CTX_set_cert_store./include/openssl/ssl.h:1120
  Original Name: SSL_CTX_get0_certificate./include/openssl/ssl.h:1121
  Original Name: SSL_CTX_get0_privatekey./include/openssl/ssl.h:1122
  Original Name: SSL_CTX_flush_sessions./include/openssl/ssl.h:1126
  Original Name: SSL_CTX_use_RSAPrivateKey_file./include/openssl/ssl.h:1179
  Original Name: SSL_CTX_use_PrivateKey_file./include/openssl/ssl.h:1180
  Original Name: SSL_CTX_use_certificate_file./include/openssl/ssl.h:1181
  Original Name: SSL_CTX_use_certificate_chain_file./include/openssl/ssl.h:1182
  Original Name: SSL_CTX_use_certificate_chain_mem./include/openssl/ssl.h:1183
  Original Name: SSL_CTX_add_session./include/openssl/ssl.h:1231
  Original Name: SSL_CTX_remove_session./include/openssl/ssl.h:1232
  Original Name: SSL_CTX_set_generate_session_id./include/openssl/ssl.h:1233
  Original Name: SSL_CTX_get_verify_mode./include/openssl/ssl.h:1246
  Original Name: SSL_CTX_get_verify_depth./include/openssl/ssl.h:1247
  Original Name: SSL_CTX_get_verify_callback./include/openssl/ssl.h:1248
  Original Name: SSL_CTX_set_verify./include/openssl/ssl.h:1249
  Original Name: SSL_CTX_set_verify_depth./include/openssl/ssl.h:1251
  Original Name: SSL_CTX_set_cert_verify_callback./include/openssl/ssl.h:1252
  Original Name: SSL_CTX_use_RSAPrivateKey./include/openssl/ssl.h:1253
  Original Name: SSL_CTX_use_RSAPrivateKey_ASN1./include/openssl/ssl.h:1254
  Original Name: SSL_CTX_use_PrivateKey./include/openssl/ssl.h:1255
  Original Name: SSL_CTX_use_PrivateKey_ASN1./include/openssl/ssl.h:1256
  Original Name: SSL_CTX_use_certificate./include/openssl/ssl.h:1257
  Original Name: SSL_CTX_use_certificate_ASN1./include/openssl/ssl.h:1258
  Original Name: SSL_CTX_get_default_passwd_cb./include/openssl/ssl.h:1260
  Original Name: SSL_CTX_set_default_passwd_cb./include/openssl/ssl.h:1261
  Original Name: SSL_CTX_get_default_passwd_cb_userdata./include/openssl/ssl.h:1262
  Original Name: SSL_CTX_set_default_passwd_cb_userdata./include/openssl/ssl.h:1263
  Original Name: SSL_CTX_check_private_key./include/openssl/ssl.h:1265
  Original Name: SSL_CTX_set_session_id_context./include/openssl/ssl.h:1268
  Original Name: SSL_CTX_set_purpose./include/openssl/ssl.h:1272
  Original Name: SSL_CTX_set_trust./include/openssl/ssl.h:1274
  Original Name: SSL_CTX_get0_param./include/openssl/ssl.h:1280
  Original Name: SSL_CTX_set1_param./include/openssl/ssl.h:1281
  Original Name: SSL_CTX_get_max_early_data./include/openssl/ssl.h:1300
  Original Name: SSL_CTX_set_max_early_data./include/openssl/ssl.h:1301
  Original Name: SSL_CTX_ctrl./include/openssl/ssl.h:1320
  Original Name: SSL_CTX_callback_ctrl./include/openssl/ssl.h:1321
  Original Name: SSL_CTX_set_ssl_version./include/openssl/ssl.h:1327
  Original Name: SSL_CTX_set_client_CA_list./include/openssl/ssl.h:1379
  Original Name: SSL_CTX_get_client_CA_list./include/openssl/ssl.h:1381
  Original Name: SSL_CTX_add_client_CA./include/openssl/ssl.h:1383
  Original Name: SSL_CTX_set_quiet_shutdown./include/openssl/ssl.h:1400
  Original Name: SSL_CTX_get_quiet_shutdown./include/openssl/ssl.h:1401
  Original Name: SSL_CTX_set_default_verify_paths./include/openssl/ssl.h:1407
  Original Name: SSL_CTX_load_verify_locations./include/openssl/ssl.h:1408
  Original Name: SSL_CTX_load_verify_mem./include/openssl/ssl.h:1410
  Original Name: SSL_get_SSL_CTX./include/openssl/ssl.h:1414
  Original Name: SSL_set_SSL_CTX./include/openssl/ssl.h:1415
  Original Name: SSL_CTX_set_ex_data./include/openssl/ssl.h:1436
  Original Name: SSL_CTX_get_ex_data./include/openssl/ssl.h:1437
  Original Name: SSL_CTX_get_ex_new_index./include/openssl/ssl.h:1438
  Original Name: SSL_CTX_set_tmp_rsa_callback./include/openssl/ssl.h:1473
  Original Name: SSL_CTX_set_tmp_dh_callback./include/openssl/ssl.h:1478
  Original Name: SSL_CTX_set_tmp_ecdh_callback./include/openssl/ssl.h:1482

*/
