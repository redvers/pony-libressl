use "net"
use "crypto"

use @SSL_new[SslST](ctx: SSLContextST tag)
use @SSL_set_verify[None](s: SslST, mode: I32, callback: Pointer[None] tag)
use @SSL_set_bio[None](s: SslST, rbio: BioST tag, wbio: BioST tag)
use @SSL_ctrl[I64](s: SslST tag, cmd: I32, larg: I64, parg: Pointer[None] tag)
use @SSL_set_accept_state[None](s: SslST tag)
use @SSL_set_connect_state[None](s: SslST tag)
use @SSL_do_handshake[I32](s: SslST)
use @SSL_write[I32](ssl: SslST tag, buf: Pointer[U8] tag, num: I32)
use @SSL_free[None](ssl: SslST tag)
use @SSL_get_peer_certificate[X509ST](s: SslST tag)

struct SslST

class SSL
  let _hostname: String
  var _ssl: SslST
  var _input: BIO
  var _output: BIO
  var _state: SSLState = SSLHandshake
  var _read_buf: Array[U8] iso = []

  new create(ctx: SSLContextST tag,
             server: Bool,
             verify: Bool,
             hostname: String = "")? =>

    _ssl = @SSL_new(ctx)
    if (NullablePointer[SslST](_ssl).is_none()) then error end
    _hostname = hostname

    let mode = if verify then I32(3) else I32(0) end
    @SSL_set_verify(_ssl, mode, Pointer[U8])

		_input = BIO.create()?
		_output = BIO.create()?

		@SSL_set_bio(_ssl, _input.bio, _output.bio)

    if
      (_hostname.size() > 0)
        and not DNS.is_ip4(_hostname)
        and not DNS.is_ip6(_hostname)
    then
      // SSL_set_tlsext_host_name
      @SSL_ctrl(_ssl, 55, 0, _hostname.cstring())
    end

    if server then
      @SSL_set_accept_state(_ssl)
    else
      @SSL_set_connect_state(_ssl)
      @SSL_do_handshake(_ssl)
    end

	fun get_peer_certificate(): X509 ? =>
		let cert: X509ST = @SSL_get_peer_certificate(_ssl)
		X509.from_certificate(cert)?

  fun state(): SSLState =>
    _state

  fun ref write(data: ByteSeq) ? =>
    if _state isnt SSLReady then error end

    if data.size() > 0 then
      @SSL_write(_ssl, data.cpointer(), data.size().i32())
    end

  fun ref can_send(): Bool =>
    """
    Returns true if there are encrypted bytes to be passed to the destination.
    """
    if (_output.ctrl_pending() > 0) then true else false end

  fun ref send(): Array[U8] iso^ ? =>
    """
    Returns encrypted bytes to be passed to the destination. Raises an error
    if no data is available.
    """
		_output.read()?

  fun ref receive(data: ByteSeq) =>
    """
    When data is received, add it to the SSL session.
    """
		_input.write(data)

    if _state is SSLHandshake then
      let r = @SSL_do_handshake(_ssl)

      if r > 0 then
				None
//        _verify_hostname()
//      else
//        match @SSL_get_error(_ssl, r)
//        | 1 => _state = SSLAuthFail
//        | 5 | 6 => _state = SSLError
//        end
      end
    end


  fun ref _verify_hostname() =>
    """
    Verify that the certificate is valid for the given hostname.
    """
    if _hostname.size() > 0 then
			try
				let cert: X509 = get_peer_certificate()?
			end
//      let ok = X509.valid_for_host(cert, _hostname)
//
//      if not cert.is_null() then
//        @X509_free(cert)
//      end
//
//      if not ok then
//        _state = SSLAuthFail
//        return
//      end
    end

    _state = SSLReady

  fun ref read(expect: USize = 0): (Array[U8] iso^ | None) =>
    """
    Returns unencrypted bytes to be passed to the application. If `expect` is
    non-zero, the number of bytes returned will be exactly `expect`. If no data
    (or less than `expect` bytes) is available, this returns None.
    """
		None
/*
    let offset = _read_buf.size()

    var len = if expect > 0 then
      if offset >= expect then
        return _read_buf = []
      end

      expect - offset
    else
      1024
    end

    let max = if expect > 0 then expect - offset else USize.max_value() end
    let pending = @SSL_pending(_ssl).usize()

    if pending > 0 then
      if expect > 0 then
        len = len.min(pending)
      else
        len = pending
      end

      _read_buf.undefined(offset + len)
      @SSL_read(_ssl, _read_buf.cpointer(offset), len.u32())
    else
      _read_buf.undefined(offset + len)
      let r =
        @SSL_read(_ssl, _read_buf.cpointer(offset), len.u32())

      if r <= 0 then
        match @SSL_get_error(_ssl, r)
        | 1 | 5 | 6 => _state = SSLError
        | 2 =>
          // SSL buffer has more data but it is not yet decoded (or something)
          _read_buf.truncate(offset)
          return None
        end

        _read_buf.truncate(offset)
      else
        _read_buf.truncate(offset + r.usize())
      end
    end

    let ready = if expect == 0 then
      _read_buf.size() > 0
    else
      _read_buf.size() == expect
    end

    if ready then
      _read_buf = []
    else
      // try and read again any pending data that SSL hasn't decoded yet
      if @BIO_ctrl_pending(_input) > 0 then
        read(expect)
      else
        ifdef "openssl_1.1.x" then
          // try and read again any data already decoded from SSL that hasn't
          // been read via `SSL_has_pending` that was added in 1.1
          // This mailing list post has a good description of what it is for:
          // https://mta.openssl.org/pipermail/openssl-users/2017-January/005110.html
          if @SSL_has_pending(_ssl) == 1 then
            read(expect)
          end
        end
      end
    end
*/

	fun ref dispose() =>
		if not (NullablePointer[SslST](_ssl).is_none()) then
			@SSL_free(_ssl)
		end

//  Original Name: SSL_new./include/openssl/ssl.h:1285

/*
  Original Name: SSL_accept./include/openssl/ssl.h:1288
  Original Name: SSL_add0_chain_cert./include/openssl/ssl.h:1008
  Original Name: SSL_add1_chain_cert./include/openssl/ssl.h:1009
  Original Name: SSL_add_client_CA./include/openssl/ssl.h:1382
  Original Name: SSL_add_dir_cert_subjects_to_stack./include/openssl/ssl.h:1187
  Original Name: SSL_add_file_cert_subjects_to_stack./include/openssl/ssl.h:1185
  Original Name: SSL_alert_desc_string./include/openssl/ssl.h:1376
  Original Name: SSL_alert_desc_string_long./include/openssl/ssl.h:1375
  Original Name: SSL_alert_type_string./include/openssl/ssl.h:1374
  Original Name: SSL_alert_type_string_long./include/openssl/ssl.h:1373
  Original Name: SSL_cache_hit./include/openssl/ssl.h:1508
  Original Name: SSL_callback_ctrl./include/openssl/ssl.h:1319
  Original Name: SSL_check_private_key./include/openssl/ssl.h:1266
  Original Name: SSL_clear_chain_certs./include/openssl/ssl.h:1011
  Original Name: SSL_clear./include/openssl/ssl.h:1124
  Original Name: SSL_connect./include/openssl/ssl.h:1289
  Original Name: SSL_copy_session_id./include/openssl/ssl.h:1203
  Original Name: SSL_ctrl./include/openssl/ssl.h:1318
  Original Name: SSL_do_handshake./include/openssl/ssl.h:1365
  Original Name: SSL_dup_CA_list./include/openssl/ssl.h:1393
  Original Name: SSL_dup./include/openssl/ssl.h:1395
  Original Name: SSL_export_keying_material./include/openssl/tls1.h:308
  Original Name: SSL_free./include/openssl/ssl.h:1286
  Original Name: SSL_get0_alpn_selected./include/openssl/ssl.h:641
  Original Name: SSL_get0_chain_certs./include/openssl/ssl.h:1010
  Original Name: SSL_get0_next_proto_negotiated./include/openssl/ssl.h:627
  Original Name: SSL_get0_param./include/openssl/ssl.h:1282
  Original Name: SSL_get0_peername./include/openssl/ssl.h:1278
  Original Name: SSL_get0_verified_chain./include/openssl/ssl.h:515
  Original Name: SSL_get1_session./include/openssl/ssl.h:1413
  Original Name: SSL_get1_supported_ciphers./include/openssl/ssl.h:1363
  Original Name: SSL_get_certificate./include/openssl/ssl.h:1397
  Original Name: SSL_get_cipher_list./include/openssl/ssl.h:1146
  Original Name: SSL_get_ciphers./include/openssl/ssl.h:1361
  Original Name: SSL_get_client_CA_list./include/openssl/ssl.h:1380
  Original Name: SSL_get_client_ciphers./include/openssl/ssl.h:1362
  Original Name: SSL_get_client_random./include/openssl/ssl.h:1487
  Original Name: SSL_get_current_cipher./include/openssl/ssl.h:1128
  Original Name: SSL_get_current_compression./include/openssl/ssl.h:1490
  Original Name: SSL_get_current_expansion./include/openssl/ssl.h:1491
  Original Name: SSL_get_default_timeout./include/openssl/ssl.h:1388
  Original Name: SSL_get_early_data_status./include/openssl/ssl.h:1309
  Original Name: SSL_get_error./include/openssl/ssl.h:1323
  Original Name: SSL_get_ex_data./include/openssl/ssl.h:1426
  Original Name: SSL_get_ex_data_X509_STORE_CTX_idx./include/openssl/ssl.h:1441
  Original Name: SSL_get_ex_new_index./include/openssl/ssl.h:1427
  Original Name: SSL_get_fd./include/openssl/ssl.h:1143
  Original Name: SSL_get_finished./include/openssl/ssl.h:734
  Original Name: SSL_get_info_callback./include/openssl/ssl.h:1418
  Original Name: SSL_get_max_early_data./include/openssl/ssl.h:1303
  Original Name: SSL_get_max_proto_version./include/openssl/ssl.h:1025
  Original Name: SSL_get_min_proto_version./include/openssl/ssl.h:1024
  Original Name: SSL_get_num_tickets./include/openssl/ssl.h:512
  Original Name: SSL_get_peer_cert_chain./include/openssl/ssl.h:1244
  Original Name: SSL_get_peer_certificate./include/openssl/ssl.h:1241
  Original Name: SSL_get_peer_finished./include/openssl/ssl.h:735
  Original Name: SSL_get_peer_signature_type_nid./include/openssl/ssl.h:1063
  Original Name: SSL_get_privatekey./include/openssl/ssl.h:1398
  Original Name: SSL_get_quiet_shutdown./include/openssl/ssl.h:1403
  Original Name: SSL_get_rbio./include/openssl/ssl.h:1154
  Original Name: SSL_get_read_ahead./include/openssl/ssl.h:1148
  Original Name: SSL_get_rfd./include/openssl/ssl.h:1144
  Original Name: SSL_get_selected_srtp_profile./include/openssl/srtp.h:140
  Original Name: SSL_get_servername./include/openssl/tls1.h:299
  Original Name: SSL_get_servername_type./include/openssl/tls1.h:300
  Original Name: SSL_get_server_random./include/openssl/ssl.h:1488
  Original Name: SSL_get_session./include/openssl/ssl.h:1412
  Original Name: SSL_get_shared_ciphers./include/openssl/ssl.h:1147
  Original Name: SSL_get_shutdown./include/openssl/ssl.h:1405
  Original Name: SSL_get_signature_type_nid./include/openssl/ssl.h:1062
  Original Name: SSL_get_srtp_profiles./include/openssl/srtp.h:139
  Original Name: SSL_get_SSL_CTX./include/openssl/ssl.h:1414
  Original Name: SSL_get_ssl_method./include/openssl/ssl.h:1371
  Original Name: SSL_get_verify_callback./include/openssl/ssl.h:1164
  Original Name: SSL_get_verify_depth./include/openssl/ssl.h:1163
  Original Name: SSL_get_verify_mode./include/openssl/ssl.h:1162
  Original Name: SSL_get_verify_result./include/openssl/ssl.h:1423
  Original Name: SSL_get_version./include/openssl/ssl.h:1324
  Original Name: SSL_get_wbio./include/openssl/ssl.h:1156
  Original Name: SSL_get_wfd./include/openssl/ssl.h:1145
  Original Name: SSL_has_matching_session_id./include/openssl/ssl.h:1235
  Original Name: SSL_is_dtls./include/openssl/ssl.h:1290
  Original Name: SSL_is_server./include/openssl/ssl.h:1291
  Original Name: SSL_library_init./include/openssl/ssl.h:1390
  Original Name: SSL_load_client_CA_file./include/openssl/ssl.h:1184
  Original Name: SSL_load_error_strings./include/openssl/ssl.h:1190
  Original Name: SSL_peek_ex./include/openssl/ssl.h:1296
  Original Name: SSL_peek./include/openssl/ssl.h:1293
  Original Name: SSL_pending./include/openssl/ssl.h:1149
  Original Name: SSL_read_early_data./include/openssl/ssl.h:1314
  Original Name: SSL_read_ex./include/openssl/ssl.h:1295
  Original Name: SSL_read./include/openssl/ssl.h:1292
  Original Name: SSL_renegotiate_abbreviated./include/openssl/ssl.h:1367
  Original Name: SSL_renegotiate./include/openssl/ssl.h:1366
  Original Name: SSL_renegotiate_pending./include/openssl/ssl.h:1368
  Original Name: SSL_rstate_string./include/openssl/ssl.h:1192
  Original Name: SSL_rstate_string_long./include/openssl/ssl.h:1194
  Original Name: SSL_select_next_proto./include/openssl/ssl.h:624
  Original Name: SSL_set0_chain./include/openssl/ssl.h:1006
  Original Name: SSL_set0_rbio./include/openssl/ssl.h:1155
  Original Name: SSL_set1_chain./include/openssl/ssl.h:1007
  Original Name: SSL_set1_groups./include/openssl/ssl.h:1016
  Original Name: SSL_set1_groups_list./include/openssl/ssl.h:1017
  Original Name: SSL_set1_host./include/openssl/ssl.h:1276
  Original Name: SSL_set1_param./include/openssl/ssl.h:1283
  Original Name: SSL_set_accept_state./include/openssl/ssl.h:1386
  Original Name: SSL_set_alpn_protos./include/openssl/ssl.h:636
  Original Name: SSL_set_bio./include/openssl/ssl.h:1153
  Original Name: SSL_set_cipher_list./include/openssl/ssl.h:1157
  Original Name: SSL_set_ciphersuites./include/openssl/ssl.h:1159
  Original Name: SSL_set_client_CA_list./include/openssl/ssl.h:1378
  Original Name: SSL_set_connect_state./include/openssl/ssl.h:1385
  Original Name: SSL_set_debug./include/openssl/ssl.h:1507
  Original Name: SSL_set_ex_data./include/openssl/ssl.h:1425
  Original Name: SSL_set_fd./include/openssl/ssl.h:1150
  Original Name: SSL_set_generate_session_id./include/openssl/ssl.h:1234
  Original Name: SSL_set_hostflags./include/openssl/ssl.h:1277
  Original Name: SSL_set_info_callback./include/openssl/ssl.h:1416
  Original Name: SSL_set_max_early_data./include/openssl/ssl.h:1304
  Original Name: SSL_set_max_proto_version./include/openssl/ssl.h:1027
  Original Name: SSL_set_min_proto_version./include/openssl/ssl.h:1026
  Original Name: SSL_set_msg_callback./include/openssl/ssl.h:504
  Original Name: SSL_set_num_tickets./include/openssl/ssl.h:511
  Original Name: SSL_set_post_handshake_auth./include/openssl/ssl.h:748
  Original Name: SSL_set_psk_use_session_callback./include/openssl/ssl.h:647
  Original Name: SSL_set_purpose./include/openssl/ssl.h:1273
  Original Name: SSL_set_quiet_shutdown./include/openssl/ssl.h:1402
  Original Name: SSL_set_read_ahead./include/openssl/ssl.h:1161
  Original Name: SSL_set_rfd./include/openssl/ssl.h:1151
  Original Name: SSL_set_session_id_context./include/openssl/ssl.h:1270
  Original Name: SSL_set_session./include/openssl/ssl.h:1230
  Original Name: SSL_set_session_secret_cb./include/openssl/ssl.h:1504
  Original Name: SSL_set_session_ticket_ext_cb./include/openssl/ssl.h:1500
  Original Name: SSL_set_session_ticket_ext./include/openssl/ssl.h:1498
  Original Name: SSL_set_shutdown./include/openssl/ssl.h:1404
  Original Name: SSL_set_SSL_CTX./include/openssl/ssl.h:1415
  Original Name: SSL_set_ssl_method./include/openssl/ssl.h:1372
  Original Name: SSL_set_state./include/openssl/ssl.h:1420
  Original Name: SSL_set_tlsext_use_srtp./include/openssl/srtp.h:137
  Original Name: SSL_set_tmp_dh_callback./include/openssl/ssl.h:1480
  Original Name: SSL_set_tmp_ecdh_callback./include/openssl/ssl.h:1484
  Original Name: SSL_set_tmp_rsa_callback./include/openssl/ssl.h:1476
  Original Name: SSL_set_trust./include/openssl/ssl.h:1275
  Original Name: SSL_set_verify_depth./include/openssl/ssl.h:1167
  Original Name: SSL_set_verify./include/openssl/ssl.h:1165
  Original Name: SSL_set_verify_result./include/openssl/ssl.h:1422
  Original Name: SSL_set_wfd./include/openssl/ssl.h:1152
  Original Name: SSL_shutdown./include/openssl/ssl.h:1369
  Original Name: SSL_state./include/openssl/ssl.h:1419
  Original Name: SSL_state_string./include/openssl/ssl.h:1191
  Original Name: SSL_state_string_long./include/openssl/ssl.h:1193
  Original Name: SSL_up_ref./include/openssl/ssl.h:1287
  Original Name: SSL_use_certificate_ASN1./include/openssl/ssl.h:1173
  Original Name: SSL_use_certificate_chain_file./include/openssl/ssl.h:1178
  Original Name: SSL_use_certificate_file./include/openssl/ssl.h:1177
  Original Name: SSL_use_certificate./include/openssl/ssl.h:1172
  Original Name: SSL_use_PrivateKey_ASN1./include/openssl/ssl.h:1171
  Original Name: SSL_use_PrivateKey_file./include/openssl/ssl.h:1176
  Original Name: SSL_use_PrivateKey./include/openssl/ssl.h:1170
  Original Name: SSL_use_RSAPrivateKey_ASN1./include/openssl/ssl.h:1169
  Original Name: SSL_use_RSAPrivateKey_file./include/openssl/ssl.h:1175
  Original Name: SSL_use_RSAPrivateKey./include/openssl/ssl.h:1168
  Original Name: SSL_verify_client_post_handshake./include/openssl/ssl.h:746
  Original Name: SSL_version./include/openssl/ssl.h:1406
  Original Name: SSL_want./include/openssl/ssl.h:1123
  Original Name: SSL_write_early_data./include/openssl/ssl.h:1315
  Original Name: SSL_write_ex./include/openssl/ssl.h:1297
  Original Name: SSL_write./include/openssl/ssl.h:1294
*/


primitive SSLHandshake
primitive SSLAuthFail
primitive SSLReady
primitive SSLError

type SSLState is (SSLHandshake | SSLAuthFail | SSLReady | SSLError)
