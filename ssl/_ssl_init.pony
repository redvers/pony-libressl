use "crypto"
use "lib:ssl"
use "lib:crypto"

use @SSL_load_error_strings[None]()
use @SSL_library_init[I32]()
use @ponyint_ssl_multithreading[Pointer[None]](count: U32)
use @CRYPTO_num_locks[I32]()
use @CRYPTO_set_locking_callback[None](cb: Pointer[None])

primitive _SSLInit
  fun _init() =>
    @SSL_load_error_strings()
    @SSL_library_init()
    let cb = @ponyint_ssl_multithreading(@CRYPTO_num_locks().u32())
    Crypto.set_locking_callback(cb)
