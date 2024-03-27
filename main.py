from Crypto.Cipher import AES
from keys import *
import struct
import sys

PK11_IV_OFFSET = 0x180
PK11_IV_SIZE   = 0x10

PK11_ENC_DATA_OFFSET = 0x190

PK11_KEYGEN_OFFSET = 0x1E

MASTER_KEY_SOURCE = bytes.fromhex("d8a2410ac6c59001c61d6a267c513f3c") # constant between dev/prod and all fw

class MarikoOemBootloader:
    def __init__(self, pk11_data):
        (self.crypt_hash, 
        self.signature, 
        self.random, 
        self.hash, 
        self.version, 
        self.size, 
        self.load_addr, 
        self.entry_point,
        self.reserved) = struct.unpack("16s256s32s32sIIII16s", pk11_data[0:0x170])

def print_keys(keygen, mkek_src, mkek, mkey):
    print("mariko_master_key_source_{:02x} = {}".format(keygen, mkek_src.hex()))
    print("master_kek_{:02x} = {}".format(keygen, mkek.hex()))
    print("master_key_{:02x} = {}".format(keygen, mkey.hex()))

def main(argv):
    if(len(argv) < 2):
        print("Invalid Args!\nUsage: {} [package1 path] [optional: -d]\n".format(argv[0]))
        return 0

    # Check if we should use dev keys.
    bek_index = 0
    if(len(argv) >= 3 and argv[2] == "-d"):
        bek_index = 1

    # Read package1 binary.
    with open(argv[1], "rb") as fp:
        pk11_data = fp.read()
    
    # Decode pk11 header.
    header = MarikoOemBootloader(pk11_data)

    # Decrypt encrypted data.
    pk11_iv = pk11_data[PK11_IV_OFFSET:PK11_IV_OFFSET + PK11_IV_SIZE]
    pk11_dec = AES.new(MARIKO_BOOT_ENC_KEY[bek_index], AES.MODE_CBC, iv=pk11_iv).decrypt(pk11_data[PK11_ENC_DATA_OFFSET:PK11_ENC_DATA_OFFSET + header.size])

    # Check if data decrypted properly.
    if(pk11_data[0x170:0x180] != pk11_dec[0x0:0x10]):
        print("Package1 Decryption Failed!")
        return 0

    # Find where the mkek sources are.
    mkek_src_offset = pk11_dec.find(b"OHAYO\n") + 0x30
    mkek_src_dev = pk11_dec[mkek_src_offset:mkek_src_offset + 0x10]
    mkek_src_prd = pk11_dec[mkek_src_offset + 0x10:mkek_src_offset + 0x20]

    # Derive master keks.
    mkek_dev = AES.new(MARIKO_KEY_ENC_KEY[1], AES.MODE_ECB).decrypt(mkek_src_dev)
    mkek_prd = AES.new(MARIKO_KEY_ENC_KEY[0], AES.MODE_ECB).decrypt(mkek_src_prd)

    # Derive master keys.
    mkey_dev = AES.new(mkek_dev, AES.MODE_ECB).decrypt(MASTER_KEY_SOURCE)
    mkey_prd = AES.new(mkek_prd, AES.MODE_ECB).decrypt(MASTER_KEY_SOURCE)

    # Read keygen version.
    keygen = int.from_bytes(pk11_dec[PK11_KEYGEN_OFFSET:PK11_KEYGEN_OFFSET + 1]) - 1

    # Print dev keys.
    print("Dev Keys:")
    print_keys(keygen, mkek_src_dev, mkek_dev, mkey_dev)

    # Print prod keys.
    print("\nProd Keys:")
    print_keys(keygen, mkek_src_prd, mkek_prd, mkey_prd)

if __name__ in "__main__":
    main(sys.argv)
