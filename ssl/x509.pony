
struct X509ST

class X509
  var x509: X509ST

  new from_certificate(cert: X509ST)? =>
    if (NullablePointer[X509ST](cert).is_none()) then error end
    x509 = cert




