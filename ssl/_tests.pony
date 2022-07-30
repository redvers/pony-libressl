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

    try
      TCPConnection(TCPConnectAuth(env.root),
          SSLConnection(SSLClientTest, sslctx.client()?),
          "evil.red",
          "443")

    end



class SSLClientTest is TCPConnectionNotify
  new iso create() => None
  fun ref connect_failed(comm: TCPConnection ref) => None

