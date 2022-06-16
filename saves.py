from Crypto.Cipher import AES
import zlib
import base64


def xor(data: bytearray, key: int) -> bytearray:
    """
    Applies XOR Cipher onto data with a static key
    """

    for i in range(len(data)):
        data[i] = data[i] ^ key

    return data


def remove_pad(save: str) -> str:
    """
        Removes the AES Padding from Geometry Dash Save files
    """
    pad = save[-1]
    if(pad < 16):
        return save[:-pad]
    return save


def decrypt_save(path: str) -> str:
    """
    Decrypts a Geometry Dash save file regardless of platform
    """
    with open(path, "rb") as f:
        save = f.read()

    # If the save is a Mac/IOS save
    if save[0] == 67:
        save = bytearray(save)
        b64 = xor(save, 0xB)
        zipped = base64.urlsafe_b64decode(b64)
        return zlib.decompress(zipped[10:], -zlib.MAX_WBITS).decode()

    else:
        cipher = AES.new(
            b"\x69\x70\x75\x39\x54\x55\x76\x35\x34\x79\x76\x5d\x69\x73\x46\x4d\x68\x35\x40\x3b\x74\x2e\x35\x77\x33\x34\x45\x32\x52\x79\x40\x7b", AES.MODE_ECB)
        return remove_pad(cipher.decrypt(save)).decode()
