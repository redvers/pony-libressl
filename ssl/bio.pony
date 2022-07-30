use @BIO_new[BioST](xtype: BiomethodST)
use @BIO_s_mem[BiomethodST]()

struct BioST
struct BiomethodST

class BIO
  let bio: BioST

  new create()? =>
    bio = @BIO_new(@BIO_s_mem())
    if (NullablePointer[BioST](bio).is_none()) then error end
