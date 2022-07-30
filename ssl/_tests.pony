use "crypto"
use "net"

actor Main
  new create(env: Env) =>
    env.out.print("What ho!")
    env.out.print("Version: " + OpenSSL.version())

    let sslctx: SSLContext iso =
      recover
        SSLContext
          .> set_client_verify(true)
          .> set_server_verify(true)
      end

    let tcpListenAuth: TCPListenAuth = TCPListenAuth(env.root)
    Listener(consume sslctx, TCPConnectAuth(env.root), env.out, USize(1))



class Listener is TCPListenNotify
  let _sslctx: SSLContext
  let _auth: TCPConnectAuth
  let _out: OutStream
  let _limit: USize
  var _host: String = ""
  var _service: String = ""
  var _count: USize = 0

  new iso create(
    sslctx: SSLContext iso,
    auth: TCPConnectAuth,
    out: OutStream,
    limit: USize)
  =>
    _sslctx = consume sslctx
    _auth = auth
    _out = out
    _limit = limit

  fun ref listening(listen: TCPListener ref) =>
    try
      (_host, _service) = listen.local_address().name()?
      _out.print("listening on " + _host + ":" + _service)
      _spawn(listen)
    else
      _out.print("couldn't get local address")
      listen.close()
    end

  fun ref not_listening(listen: TCPListener ref) =>
    _out.print("not listening")
    listen.close()

  fun ref connected(listen: TCPListener ref): TCPConnectionNotify iso^ ? =>
    try
      let ssl = _sslctx.server()?
      _out.print("Server starting with SSL")
      let server = SSLConnection(ServerSide(_out), consume ssl)

      _spawn(listen)
      server
    else
      _out.print("couldn't create server side")
      error
    end

  fun ref _spawn(listen: TCPListener ref) =>
		None
/*
    if (_limit > 0) and (_count >= _limit) then
      listen.dispose()
      return
    end

    _count = _count + 1
    _out.print("spawn " + _count.string())

    try
      _out.print("client starting")
      TCPConnection(
        _auth,
        SSLConnection(ClientSide(_out), _sslctx.client()?),
        _host,
        _service)
    else
      _out.print("couldn't create client side")
      listen.close()
    end
*/


class ServerSide is TCPConnectionNotify
  let _out: OutStream

  new iso create(out: OutStream) =>
    _out = out

  fun ref accepted(conn: TCPConnection ref) =>
    try
      (let host, let service) = conn.remote_address().name()?
      _out.print("accepted from " + host + ":" + service)
      conn.write("server says hi")
    end

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    _out.print(consume data)
    conn.dispose()
    true

  fun ref closed(conn: TCPConnection ref) =>
    _out.print("server closed")

  fun ref connect_failed(conn: TCPConnection ref) =>
    _out.print("connect failed")
