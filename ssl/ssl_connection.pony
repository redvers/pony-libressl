use "collections"
use "net"

class SSLConnection is TCPConnectionNotify
  let _notify: TCPConnectionNotify
  let _ssl: SSL
  var _connected: Bool = false
  var _expect: USize = 0
  var _closed: Bool = false
  let _pending: List[ByteSeq] = _pending.create()
  var _accept_pending: Bool = false

  new iso create(notify: TCPConnectionNotify iso, ssl: SSL iso) =>
  """
   Initialise with a wrapped protocol and an SSL session.
  """
    _notify = consume notify
    _ssl = consume ssl

  fun ref accepted(conn: TCPConnection ref) =>
    """
    Swallow this event until the handshake is complete.
    """
    _accept_pending = true
    _poll(conn)

  fun ref connecting(conn: TCPConnection ref, count: U32) =>
    """
    Forward to the wrapped protocol.
    """
    _notify.connecting(conn, count)

  fun ref connected(conn: TCPConnection ref) =>
    """
    Swallow this event until the handshake is complete.
    """
    _poll(conn)

  fun ref connect_failed(conn: TCPConnection ref) =>
    """
    Forward to the wrapped protocol.
    """
    _notify.connect_failed(conn)

  fun ref sent(conn: TCPConnection ref, data: ByteSeq): ByteSeq =>
    """
    Pass the data to the SSL session and check for both new application data
    and new destination data.
    """
    let notified = _notify.sent(conn, data)
    if _connected then
      try
        _ssl.write(notified)?
      else
        return ""
      end
    else
      _pending.push(notified)
    end

    _poll(conn)
    ""

  fun ref sentv(conn: TCPConnection ref, data: ByteSeqIter): ByteSeqIter =>
    let ret = recover val Array[ByteSeq] end
    let data' = _notify.sentv(conn, data)
    for bytes in data'.values() do
      if _connected then
        try
          _ssl.write(bytes)?
        else
          return ret
        end
      else
        _pending.push(bytes)
      end
    end

    _poll(conn)
    ret

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    """
    Pass the data to the SSL session and check for both new application data
    and new destination data.
    """
    _ssl.receive(consume data)
    _poll(conn)
    true




  fun ref _poll(conn: TCPConnection ref) =>
    """
    Checks for both new application data and new destination data. Informs the
    wrapped protocol that is has connected when the handshake is complete.
    """
    match _ssl.state()
    | SSLReady =>
      if not _connected then
        _connected = true
        if _accept_pending then
          _notify.accepted(conn)
        else
          _notify.connected(conn)
        end

//        match _notify
//        | let alpn_notify: ALPNProtocolNotify =>
//          alpn_notify.alpn_negotiated(conn, _ssl.alpn_selected())
//        end

        try
          while _pending.size() > 0 do
            _ssl.write(_pending.shift()?)?
          end
        end
      end
    | SSLAuthFail =>
      _notify.auth_failed(conn)

      if not _closed then
        conn.close()
      end

      return
    | SSLError =>
      if not _closed then
        conn.close()
      end

      return
    end

    try
      var received_called: USize = 0

      while true do
        let r = _ssl.read(_expect)

        if r isnt None then
          received_called = received_called + 1
          _notify.received(
            conn,
            (consume r) as Array[U8] iso^,
            received_called)
        else
          break
        end
      end
    end

    try
      while _ssl.can_send() do
        conn.write_final(_ssl.send()?)
      end
    end

  fun ref expect(conn: TCPConnection ref, qty: USize): USize =>
    """
    Keep track of the expect count for the wrapped protocol. Always tell the
    TCPConnection to read all available data.
    """
    _expect = _notify.expect(conn, qty)
    0

  fun ref closed(conn: TCPConnection ref) =>
    """
    Forward to the wrapped protocol.
    """
    _closed = true

    _poll(conn)
    _ssl.dispose()

    _connected = false
    _pending.clear()
    _notify.closed(conn)

  fun ref throttled(conn: TCPConnection ref) =>
    """
    Forward to the wrapped protocol.
    """
    _notify.throttled(conn)

  fun ref unthrottled(conn: TCPConnection ref) =>
    """
    Forward to the wrapped protocol.
    """
    _notify.unthrottled(conn)



