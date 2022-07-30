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

  fun ref connect_failed(conn: TCPConnection ref) => None
