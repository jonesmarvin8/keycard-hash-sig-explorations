"""Minimal PC/SC client over the system libpcsclite (ctypes, no dependencies)."""

import ctypes

_lib = ctypes.CDLL("libpcsclite.so.1")

SCARD_SCOPE_SYSTEM = 2
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1 = 1, 2
SCARD_LEAVE_CARD = 0

# pcsclite on Linux: SCARDCONTEXT/SCARDHANDLE and DWORD are `long`/`unsigned long`.
_hctx = ctypes.c_long
_dword = ctypes.c_ulong


class _IoRequest(ctypes.Structure):
    _fields_ = [("dwProtocol", _dword), ("cbPciLength", _dword)]


def _check(rv, what):
    if rv != 0:
        raise OSError(f"{what} failed: 0x{rv & 0xFFFFFFFF:08X}")


class Reader:
    def __init__(self, index=0):
        self.ctx = _hctx()
        _check(_lib.SCardEstablishContext(SCARD_SCOPE_SYSTEM, None, None, ctypes.byref(self.ctx)),
               "SCardEstablishContext")
        size = _dword(0)
        _check(_lib.SCardListReaders(self.ctx, None, None, ctypes.byref(size)), "SCardListReaders")
        buf = ctypes.create_string_buffer(size.value)
        _check(_lib.SCardListReaders(self.ctx, None, buf, ctypes.byref(size)), "SCardListReaders")
        names = [n for n in buf.raw[: size.value].split(b"\x00") if n]
        self.name = names[index]
        self.card = _hctx()
        self.proto = _dword()
        _check(_lib.SCardConnect(self.ctx, ctypes.c_char_p(self.name), SCARD_SHARE_SHARED,
                                 SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                 ctypes.byref(self.card), ctypes.byref(self.proto)), "SCardConnect")
        self.pci = _IoRequest(self.proto.value, ctypes.sizeof(_IoRequest))

    def transmit(self, apdu):
        send = (ctypes.c_ubyte * len(apdu))(*apdu)
        recv = (ctypes.c_ubyte * 65538)()
        rlen = _dword(len(recv))
        _check(_lib.SCardTransmit(self.card, ctypes.byref(self.pci), send, _dword(len(apdu)),
                                  None, recv, ctypes.byref(rlen)), "SCardTransmit")
        out = bytes(recv[: rlen.value])
        return out[:-2], out[-2], out[-1]

    def close(self):
        _lib.SCardDisconnect(self.card, SCARD_LEAVE_CARD)
        _lib.SCardReleaseContext(self.ctx)
