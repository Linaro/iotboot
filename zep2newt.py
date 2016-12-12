#!/usr/bin/python2
import mmap
import os
import struct
import sys
from argparse import ArgumentParser
import newtimg
from ctypes import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

DEBUG = False

################################################################################
def get_args():
    parser = ArgumentParser(description='Script to create images on a format \
                            that Mynewts bootloader expects')

    parser.add_argument('--bin', required=True, dest='binary_file', \
                        help='Name of *.bin file (input)')

    parser.add_argument('--key', required=False, dest='key_file', \
                        help='Name of private key file (*.pem format)')

    parser.add_argument('--out', required=False, dest='image_file', \
                        default='zephyr.img.bin', \
                        help='Name of *.img file (output)')

    parser.add_argument('--sig', required=False, dest='sig_type', \
                        default='SHA256', \
                        help='Type of signature <SHA256|RSA|EC>')

    parser.add_argument('--off', required=False, dest='flash_offs_addr', \
                        default='0x08020000', \
                        help='Offset for the binary in flash (at what address \
                        should it be flashed?)')

    parser.add_argument('--vtoff', required=False, dest='vtable_offs', \
                        default=str(hex(newtimg.OFFSET_VECTOR_TABLE)), \
                        help='Offset to vector table in HEX (default: 0x80)')

    parser.add_argument('--pad', required=False, \
                        help='Pad file with 0xff up to this size (in hex)')

    parser.add_argument('--bit', required=False, action="store_true", \
                        default=False, \
                        help='Whether to add the Boot Image Trailer to the \
                        padded image or not (default: False)')

    parser.add_argument('--verbose', required=False, action="store_true", \
                        default=False, \
                        help='Enable verbose mode')

    parser.add_argument('--version', action='version', version='%(prog)s 1.0')

    parser.add_argument('-f', required=False, action="store_true", \
                        default=False, \
                        help='Flash using JLinkExe')

    return parser.parse_args()

# ################################################################################
# def create_header(binary_file, sig_type, vtable_offs):
#     """
#     Create a header on a format that Mynewt's bootloader expects. Based on
#     signature type it updates, TLV size, flags and key ID (if RSA). This
#     function also updates/stores the offset to the vector table in the binary.
#     For example in Mynewt the offset is 0x20, but in Zephyr it's expected that
#     the vector table is at an address % 128 and therefore 0x80 should be used
#     there instead (which is the default in this script).
#     """
#     # The SHA256 hash is always used and therefore we use that as default
#     tlv_size = SHA256_DIGEST_SIZE + 4
#     flags = IMAGE_F_SHA256
#     key_id = 0
# 
#     if sig_type == "RSA":
#         tlv_size = tlv_size + 4 + RSA_SIZE
#         keyId = 0 # FIXME
#         flags =  IMAGE_F_PKCS15_RSA2048_SHA256 | IMAGE_F_SHA256
#     elif sig_type == "EC":
#         tlv_size = tlv_size + 4 + ECDSA_SIZE
#         flags = IMAGE_F_ECDSA224_SHA256 | IMAGE_F_SHA256
# 
#     image_size = 0
#     # Get the correct size for the image
#     image_size = os.path.getsize(binary_file)
#     if DEBUG:
#         print("[*] Binary size %d (0x%x) of %s" % (image_size, image_size, binary_file))
# 
#     hdr = bytearray(struct.pack('I', IMAGE_MAGIC) +
#                     struct.pack('H', tlv_size) +
#                     struct.pack('B', key_id) + # Key ID
#                     struct.pack('B', 0) + # PAD 1
#                     struct.pack('H', vtable_offs) + # New HDR SIZE
#                     struct.pack('H', 0) + # PAD 2
#                     struct.pack('I', image_size) + # img size
#                     struct.pack('I', flags) + # Flags
#                     struct.pack('B', 1) + # Major
#                     struct.pack('B', 0) + # Minor
#                     struct.pack('H', 0) + # Revision
#                     struct.pack('I', 0) + # Build number
#                     struct.pack('I', 0)) # PAD3
#     if DEBUG:
#         with open(binary_file + ".hdr", "w+b") as f:
#             f.write(hdr)
#             f.close()
#     return hdr
# 
# ################################################################################
# def write_partial_img(binary_file, image_file, hdr, vtable_offs):
#     try:
#         with open(binary_file, "rb") as f:
#             image = f.read()
#             f.close()
#         if DEBUG:
#             print("[*] Read %d bytes from %s" % (len(image), binary_file))
# 
#     except (OSError, IOError):
#         print("[ERROR]: Cannot open %s" % (binary_file))
#         sys.exit(1)
# 
#     try:
#         with open(image_file, "w+b") as f:
#             f.write(hdr)
#             # Calculate how much to pad before the actual image with the vector
#             # table starts.
#             f.write('\xFF' * (vtable_offs - IMAGE_HEADER_SIZE))
#             f.write(image)
#             f.close()
#         if DEBUG:
#             sz = os.path.getsize(image_file)
#             print("[*] Wrote %d (0x%x) bytes to %s" % (sz, sz, image_file))
# 
#     except (OSError, IOError):
#         print("[ERROR]: Cannot write to %s" % (image_file))
#         sys.exit(1)
# 
# 
# ################################################################################
# def calculate_hash(image_file, sha256):
#     try:
#         with open(image_file, "rb") as f:
#             sha256.update(f.read())
#             f.close()
# 
#     except IOError:
#         print("[ERROR]: Cannot open %s" % (image_file))
#         sys.exit(1)
# 
#     digest = sha256.hexdigest()
#     if DEBUG:
#         print("[*] Hash of intermediate image: %s" % digest)
#     return digest
# 
# ################################################################################
# def append_hash(image_file, digest):
#     try:
#         with open(image_file, "ab") as f:
#             # Start by settings the TLV type
#             # https://github.com/apache/incubator-mynewt-newt/blob/master/newt/image/image.go#L109-L116
#             tlv_type = struct.pack('b', IMAGE_TLV_SHA256)
# 
#             # Next 1 byte padding
#             tlv_pad = '\x00'
# 
#             # Finally the size of the TLV, for SHA256 that is 32 bytes
#             tlv_len = struct.pack('h', SHA256_DIGEST_SIZE)
# 
#             f.write(tlv_type)
#             f.write(tlv_pad)
#             f.write(tlv_len)
#             f.write(digest.decode('hex'))
#             f.close()
# 
#     except IOError:
#         print("[ERROR]: Cannot open/append to %s" % (image_file))
#         sys.exit(1)
# 
# ################################################################################
# def append_rsa_signature(image_file, key_file, sha256):
#     signature = None
#     try:
#         with open(key_file, "rb") as f:
#             rsa_key = RSA.importKey(f.read())
#             f.close()
#         rsa = PKCS1_v1_5.new(rsa_key)
#         signature = rsa.sign(sha256)
# 
#     except (OSError, IOError):
#         print("[ERROR]: Cannot open %s" % (key_file))
#         sys.exit(1)
# 
#     try:
#         with open(image_file, "ab") as f:
#             # Start by settings the TLV type
#             # https://github.com/apache/incubator-mynewt-newt/blob/master/newt/image/image.go#L109-L116
#             tlv_type = struct.pack('b', IMAGE_TLV_RSA2048)
# 
#             # Next 1 byte padding
#             tlv_pad = '\x00'
# 
#             # Finally the size of the TLV, for SHA256 that is 32 bytes
#             tlv_len = struct.pack('h', RSA_SIZE)
# 
#             f.write(tlv_type)
#             f.write(tlv_pad)
#             f.write(tlv_len)
#             f.write(signature)
#             f.close()
# 
#     except (OSError, IOError):
#         print("[ERROR]: Cannot open/append to %s" % (image_file))
#         sys.exit(1)
# 
# 
# ################################################################################
# def create_jlink_script(image_file, offset, erase):
#     """
#     Creates a jlink script to flash the created binary.
# 
#     @erase: whether the script first shall erase or not when flashing.
#     @offset: where in flash to store the image.
#     """
#     jlink_file = "flash_zephyr.jlink"
#     try:
#         with open(jlink_file, "w+") as f:
#             f.write("device nrf52\n")
#             f.write("power on\n")
#             f.write("sleep 10\n")
#             f.write("si 1\n")
#             f.write("speed auto\n")
#             if erase:
#                 f.write("erase\n")
#             f.write("loadfile %s %s\n" % (image_file, hex(int(offset, 16))))
#             f.write("q\n")
#             f.close()
#         if DEBUG:
#             print("\n[*] To flash the Image for nrf52 run:")
#             print("     JLinkExe -CommanderScript %s" % jlink_file)
# 
#     except IOError:
#         print("[ERROR]: Cannot create to %s" % (jlink_file))
#         sys.exit(1)
# 
# ################################################################################
# def create_jlink_bit_script(bit_file, bitoffset="0x7bff8"):
#     jlink_file = "flash_bit.jlink"
#     try:
#         with open(jlink_file, "w+") as f:
#             f.write("device nrf52\n")
#             f.write("power on\n")
#             f.write("sleep 10\n")
#             f.write("si 1\n")
#             f.write("speed auto\n")
#             f.write("loadfile %s %s\n" % (bit_file, hex(int(bitoffset, 16))))
#             f.write("q\n")
#             f.close()
#         if DEBUG:
#             print("\n[*] To flash Boot Image Trailer for nrf52 run:")
#             print("     JLinkExe -CommanderScript %s" % jlink_file)
# 
#     except IOError:
#         print("[ERROR]: Cannot create to %s" % (jlink_file))
#         sys.exit(1)
# 
# ################################################################################
# def create_jlink_clear_bit_script(bit_file, bitoffset="0x7bff8"):
#     jlink_file = "flash_clear_bit.jlink"
#     try:
#         with open(jlink_file, "w+") as f:
#             f.write("device nrf52\n")
#             f.write("power on\n")
#             f.write("sleep 10\n")
#             f.write("si 1\n")
#             f.write("speed auto\n")
#             f.write("loadfile %s %s\n" % (bit_file, hex(int(bitoffset, 16))))
#             f.write("q\n")
#             f.close()
#         if DEBUG:
#             print("\n[*] To clear Boot Image Trailer for nrf52 run:")
#             print("     JLinkExe -CommanderScript %s" % jlink_file)
# 
#     except IOError:
#         print("[ERROR]: Cannot create to %s" % (jlink_file))
#         sys.exit(1)
# ################################################################################
# def pad_binary(binary_file, pad_size, boot_magic=False):
#     try:
#         # Get the correct size for the image
#         size = pad_size - os.path.getsize(binary_file)
#         if boot_magic:
#             size -= 8
# 
#         if size <= 0:
#             print("Nothing to pad\n")
#             return
# 
#         with open(binary_file, "ab") as f:
#             f.write(('\xff') * size)
#             if boot_magic:
#                 f.write(struct.pack('I', BOOT_IMG_MAGIC) )
#                 f.write(('\xff') * 4)
#             f.close()
# 
#     except (OSError, IOError):
#         print("[ERROR]: Cannot open/append to %s" % (binary_file))
#         sys.exit(1)
# 
# ################################################################################

class Signature(object):
    """
    Sign an image appropriately.
    """

    def compute(self, payload, key_file):
        # Base computes sha256.
        ctx = SHA256.new()
        ctx.update(payload)
        self.hash = ctx.digest()
        self.ctx = ctx

    def get_trailer(self):
        return struct.pack('bxh32s', newtimg.IMAGE_TLV_SHA256,
                len(self.hash),
                self.hash)

    def trailer_len(self):
        return 32 + 4

    def get_flags(self):
        return newtimg.IMAGE_F_SHA256

class RSASignature(Signature):

    def compute(self, payload, key_file):
        super(RSASignature, self).compute(payload, key_file)
        with open(key_file, 'rb') as f:
            rsa_key = RSA.importKey(f.read())
        rsa = PKCS1_v1_5.new(rsa_key)
        self.signature = rsa.sign(self.ctx)

    def trailer_len(self):
        return super(RSASignature, self).trailer_len() + newtimg.RSA_SIZE

    def get_trailer(self):
        buf = bytearray(super(RSASignature, self).get_trailer())
        buf.extend(struct.pack('bxh', newtimg.IMAGE_TLV_RSA2048,
                newtimg.RSA_SIZE))
        buf.extend(self.signature)
        return buf

    def get_flags(self):
        return newtimg.IMAGE_F_PKCS15_RSA2048_SHA256 | newtimg.IMAGE_F_SHA256

sigs = {
        'SHA256': Signature,
        'RSA': RSASignature,
        }

class Convert():
    def __init__(self, args):
        self.args = args
        if args.verbose:
            for a in vars(args):
                print("Arg -> {}: {}".format(a, getattr(args, a)))
            self.debug = True
        else:
            self.debug = False

        self.vtable_offs = int(args.vtable_offs, 16)

        self.load_image(args.binary_file)
        self.validate_header()

        sig = sigs[args.sig_type]()
        header = self.make_header(sig)
        assert len(header) == 32
        self.image[:len(header)] = header

        sig.compute(self.image, args.key_file)
        self.trailer = sig.get_trailer()

        self.image.extend(self.trailer)

        if args.bit:
            self.add_trailer(args.pad)

        self.save_image(args.image_file)

    def load_image(self, name):
        with open(name, 'rb') as f:
            image = f.read()
        self.image = bytearray(image)

    def save_image(self, name):
        with open(name, 'wb') as f:
            f.write(self.image)

    def validate_header(self):
        """Ensure that the image has space for a header

        If the image is build with CONFIG_BOOT_HEADER off, the vector
        table will be at the beginning, rather than the zero padding.
        Verify that the padding is present.
        """
        if self.image[:self.vtable_offs] != ('\x00' * self.vtable_offs):
            raise Exception("Image does not have space for header")

    def make_header(self, sig):
        image_size = len(self.image) - self.vtable_offs
        tlv_size = sig.trailer_len()
        key_id = 0
        hd = struct.pack('IHBxHxxIIBBHI4x',
                newtimg.IMAGE_MAGIC,
                tlv_size,
                key_id,
                self.vtable_offs,
                image_size,
                sig.get_flags(),
                1, 0, 0, 0)
        return hd

    def add_trailer(self, pad):
        """
        Add the image trailer, to indicate to the bootloader that this
        image should be flashed
        """
        if not pad:
            raise Exception("Must specify image length with --pad to use --bit")
        pad = int(pad, 16)

        if len(self.image) > pad:
            raise Exception("Image is too large for padding")

        self.image.extend('\xFF' * (pad - len(self.image)))

        magic = struct.pack('4I', *newtimg.BOOT_IMG_MAGIC)
        pos = pad - 402
        self.image[pos:pos + len(magic)] = magic

def main(argv):
    args = get_args()
    erase = False

    conv = Convert(args)
# 
#     if args.verbose:
#         for a in vars(args):
#             print("Arg -> %s: %s" % (a, getattr(args, a)))
#         global DEBUG
#         DEBUG = True
# 
#     if (args.pad):
#         pad_size = int(args.pad, 16)
#         pad_binary(args.binary_file, pad_size, args.bit)
#         sys.exit(1)
# 
#     # Since it's a hex string, let's convert to an integer instead
#     vtable_offs = int(args.vtable_offs, 16)
# 
#     # Create the header first
#     hdr = create_header(args.binary_file, args.sig_type, vtable_offs)
# 
#     # Write the image itself
#     write_partial_img(args.binary_file, args.image_file, hdr, vtable_offs)
# 
#     # We must use SHA256 from Crypto, since the RSA signature also uses some
#     # ASN.1 / oid, that will be created when using the SHA256 from Crypto
#     # (compared to hashlib that just do a pure hash).
#     sha256 = SHA256.new()
# 
#     # Now we have a header and the binary itself and we should get the hash of
#     # those concatenated.
#     digest = calculate_hash(args.image_file, sha256)
#     append_hash(args.image_file, digest)
# 
#     if args.sig_type == "RSA":
#         append_rsa_signature(args.image_file, args.key_file, sha256)
#     elif args.sig_type == "EC":
#         print("[ERROR]: ECDSA not implemented")
#         sys.exit(1)
# 
#     print("[*] Successfully created: %s" % args.image_file)
# 
#     # Misc function related to flashing
#     create_jlink_script(args.image_file, args.flash_offs_addr, erase)
#     curdir = os.path.dirname(sys.argv[0])
#     create_jlink_bit_script(curdir + "/boot_image_trailer.bin")
#     create_jlink_clear_bit_script(curdir + "/empty_boot_image_trailer.bin")
# 
#     # Should we try flash?
#     if args.f:
#         os.system("JLinkExe -CommanderScript flash_zephyr.jlink")

if __name__ == "__main__":
    main(sys.argv)
