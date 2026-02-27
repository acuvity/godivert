package godivert

import (
	"encoding/binary"
	"fmt"
)

// See : https://reqrypt.org/windivert-doc.html#divert_address
// Offsets in the raw buffer (WinDivert 2.2):
//
//	0..7   : Timestamp (int64)
//	8..15  : Bitfield word (uint64): Layer/Event + flags
//	16..   : Union; for NETWORK layer, union starts with IfIdx/SubIfIdx (uint32/uint32)
const (
	addrOffTimestamp = 0
	addrOffBits      = 8
	addrOffUnion     = 16

	addrOffIfIdx    = addrOffUnion + 0
	addrOffSubIfIdx = addrOffUnion + 4

	windivertAddressSize = 80
)

type WinDivertAddress struct {
	raw [windivertAddressSize]byte
}

// NewWinDivertAddress creates a new WinDivertAddress with default values.
func NewWinDivertAddress() *WinDivertAddress {
	return &WinDivertAddress{}
}

// Raw returns pointer to the underlying buffer (use when calling into WinDivert DLL).
func (w *WinDivertAddress) Raw() *[windivertAddressSize]byte {
	return &w.raw
}

// Size returns the binary size of WinDivertAddress.
func (w *WinDivertAddress) Size() int {
	return windivertAddressSize
}

func (w *WinDivertAddress) bits() uint64 {
	return binary.LittleEndian.Uint64(w.raw[addrOffBits : addrOffBits+8])
}

func (w *WinDivertAddress) setBits(v uint64) {
	binary.LittleEndian.PutUint64(w.raw[addrOffBits:addrOffBits+8], v)
}

func (w *WinDivertAddress) flag(bit uint) bool {
	return ((w.bits() >> bit) & 1) != 0
}

func (w *WinDivertAddress) setFlag(bit uint, on bool) {
	b := w.bits()
	if on {
		b |= (uint64(1) << bit)
	} else {
		b &^= (uint64(1) << bit)
	}
	w.setBits(b)
}

// Bit positions in the WinDivert 2.2 bitfield word (offset 8).
const (
	bitSniffed     = 16
	bitOutbound    = 17
	bitLoopback    = 18
	bitImpostor    = 19
	bitIPv6        = 20
	bitIPChecksum  = 21
	bitTCPChecksum = 22
	bitUDPChecksum = 23
)

// Timestamp (read/write)
func (w *WinDivertAddress) Timestamp() int64 {
	return int64(binary.LittleEndian.Uint64(w.raw[addrOffTimestamp : addrOffTimestamp+8]))
}

func (w *WinDivertAddress) SetTimestamp(ts int64) {
	binary.LittleEndian.PutUint64(w.raw[addrOffTimestamp:addrOffTimestamp+8], uint64(ts))
}

// IfIdx/SubIfIdx (NETWORK union fields)
func (w *WinDivertAddress) IfIdx() uint32 {
	return binary.LittleEndian.Uint32(w.raw[addrOffIfIdx : addrOffIfIdx+4])
}

func (w *WinDivertAddress) SetIfIdx(v uint32) {
	binary.LittleEndian.PutUint32(w.raw[addrOffIfIdx:addrOffIfIdx+4], v)
}

func (w *WinDivertAddress) SubIfIdx() uint32 {
	return binary.LittleEndian.Uint32(w.raw[addrOffSubIfIdx : addrOffSubIfIdx+4])
}

func (w *WinDivertAddress) SetSubIfIdx(v uint32) {
	binary.LittleEndian.PutUint32(w.raw[addrOffSubIfIdx:addrOffSubIfIdx+4], v)
}

// Add helper methods to handle flags through Flags field
func (w *WinDivertAddress) SetFlags(flags uint8) {
	w.SetOutbound(flags&0x1 == 1)
	w.setFlag(bitLoopback, (flags>>1)&0x1 == 1)
	w.setFlag(bitImpostor, (flags>>2)&0x1 == 1)
	w.setFlag(bitIPChecksum, (flags>>3)&0x1 == 1)
	w.setFlag(bitTCPChecksum, (flags>>4)&0x1 == 1)
	w.setFlag(bitUDPChecksum, (flags>>5)&0x1 == 1)
}

func (w *WinDivertAddress) GetFlags() uint8 {
	var flags uint8

	if w.Outbound() {
		flags |= 1 << 0
	}

	if w.Loopback() {
		flags |= 1 << 1
	}

	if w.Impostor() {
		flags |= 1 << 2
	}

	if w.PseudoIPChecksum() {
		flags |= 1 << 3
	}

	if w.PseudoTCPChecksum() {
		flags |= 1 << 4
	}

	if w.PseudoUDPChecksum() {
		flags |= 1 << 5
	}

	return flags & 0x0F
}

func (w *WinDivertAddress) SetLayer(layer uint8) {
	// Layer is bits 0..7 of the bitfield word
	b := w.bits()
	b &^= 0xFF
	b |= uint64(layer)
	w.setBits(b)
}

func (w *WinDivertAddress) GetLayer() uint8 {
	return uint8(w.bits() & 0xFF)
}

// Returns the direction of the packet
// WinDivertDirectionInbound (true) for inbounds packets
// WinDivertDirectionOutbounds (false) for outbounds packets
func (w *WinDivertAddress) Direction() Direction {
	return Direction(!w.Outbound())
}

func (w *WinDivertAddress) Outbound() bool {
	return w.flag(bitOutbound)
}

func (w *WinDivertAddress) SetOutbound(v bool) {
	w.setFlag(bitOutbound, v)
}

// Returns true if the packet is a loopback packet
func (w *WinDivertAddress) Loopback() bool {
	return w.flag(bitLoopback)
}

// Returns true if the packet is an impostor
func (w *WinDivertAddress) Impostor() bool {
	return w.flag(bitImpostor)
}

// Returns true if the packet uses a pseudo IP checksum
func (w *WinDivertAddress) PseudoIPChecksum() bool {
	return w.flag(bitIPChecksum)
}

// Returns true if the packet uses a pseudo TCP checksum
func (w *WinDivertAddress) PseudoTCPChecksum() bool {
	return w.flag(bitTCPChecksum)
}

// Returns true if the packet uses a pseudo UDP checksum
func (w *WinDivertAddress) PseudoUDPChecksum() bool {
	return w.flag(bitUDPChecksum)
}

func (w *WinDivertAddress) String() string {
	return fmt.Sprintf("{\n"+
		"\t\tTimestamp=%d\n"+
		"\t\tInteface={IfIdx=%d SubIfIdx=%d}\n"+
		"\t\tDirection=%v\n"+
		"\t\tLoopback=%t\n"+
		"\t\tImpostor=%t\n"+
		"\t\tPseudoChecksum={IP=%t TCP=%t UDP=%t}\n"+
		"\t}",
		w.Timestamp(), w.IfIdx(), w.SubIfIdx(), w.Direction(), w.Loopback(), w.Impostor(),
		w.PseudoIPChecksum(), w.PseudoTCPChecksum(), w.PseudoUDPChecksum())
}

// MarshalBinary implements the encoding.BinaryMarshaler interface
func (w *WinDivertAddress) MarshalBinary() ([]byte, error) {
	buf := make([]byte, w.Size())
	copy(buf, w.raw[:])
	return buf, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface
func (w *WinDivertAddress) UnmarshalBinary(data []byte) error {
	if len(data) < w.Size() {
		return fmt.Errorf("data too short for WinDivertAddress: got %d bytes, want %d", len(data), w.Size())
	}
	copy(w.raw[:], data[:w.Size()])
	return nil
}
