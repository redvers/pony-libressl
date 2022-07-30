use @BIO_new[BioST](xtype: BiomethodST)
use @BIO_s_mem[BiomethodST]()
use @BIO_ctrl_pending[U64](b: BioST tag)
use @BIO_read[I32](b: BioST tag, data: Pointer[U8] tag, len: I32)
use @BIO_write[I32](b: BioST tag, data: Pointer[U8] tag, len: I32)

struct BioST
struct BiomethodST

class BIO
  let bio: BioST

  new create()? =>
    bio = @BIO_new(@BIO_s_mem())
    if (NullablePointer[BioST](bio).is_none()) then error end

  fun ctrl_pending(): U64 =>
    @BIO_ctrl_pending(bio)

  fun read(): Array[U8] iso^ ? =>
    let len: U64 = ctrl_pending()
    if len == 0 then error end

    let buf = recover Array[U8] .> undefined(len.usize()) end
    @BIO_read(bio, buf.cpointer(), buf.size().i32())
    consume buf

  fun write(data: ByteSeq): I32 =>
    @BIO_write(bio, data.cpointer(), data.size().i32())



