package mlkem

// #include "../../libs/opengm_pqc.h"
import "C"

import (
	"crypto/rand"
	"runtime"
	"unsafe"

	_ "github.com/opengm-libs/opengm_pqc/goapi"
)

const EncapKeySize768 = 1184
const DecapKeySize768 = 2400
const CipherSize768 = 1088

type Mlkem768DecapKey struct {
	p unsafe.Pointer
}

type Mlkem768EncapKey struct {
	p unsafe.Pointer
}

func newMlkem768DecapKey(p unsafe.Pointer) *Mlkem768DecapKey {
	dk := &Mlkem768DecapKey{p}
	runtime.SetFinalizer(dk, func(dk *Mlkem768DecapKey) {
		dk.Drop()
	})
	return dk
}

func newMlkem768EncapKey(p unsafe.Pointer) *Mlkem768EncapKey {
	ek := &Mlkem768EncapKey{p}
	runtime.SetFinalizer(ek, func(ek *Mlkem768EncapKey) {
		ek.Drop()
	})
	return ek
}

func Mlkem768KeyGen() *Mlkem768DecapKey {
	d := make([]byte, 32)
	z := make([]byte, 32)

	rand.Read(d)
	rand.Read(z)

	return newMlkem768DecapKey(C.mlkem768_keygen_internal((*C.uint8_t)(unsafe.SliceData(d)), (*C.uint8_t)(unsafe.SliceData(z))))
}

func (dk *Mlkem768DecapKey) EncapKey() *Mlkem768EncapKey {
	return newMlkem768EncapKey(C.mlkem768_encapkey(dk.p))
}

func (dk *Mlkem768DecapKey) Encode() []byte {
	b := make([]byte, DecapKeySize1024)
	C.mlkem768_decapkey_encode((*C.uint8_t)(unsafe.SliceData(b)), dk.p)
	return b
}

func (dk *Mlkem768DecapKey) Decap(c []byte) []byte {
	key := make([]byte, 32)
	C.mlkem768_decap((*C.uint8_t)(unsafe.SliceData(key)), (*C.uint8_t)(unsafe.SliceData(c)), dk.p)
	return key
}

func (ek *Mlkem768EncapKey) Encode() []byte {
	b := make([]byte, EncapKeySize1024)
	C.mlkem768_encapkey_encode((*C.uint8_t)(unsafe.SliceData(b)), ek.p)
	return b
}

func (ek *Mlkem768EncapKey) Encap() ([]byte, []byte) {
	key := make([]byte, 32)
	c := make([]byte, CipherSize1024)
	m := make([]byte, 32)
	rand.Read(m)

	C.mlkem768_encap_internal((*C.uint8_t)(unsafe.SliceData(key)), (*C.uint8_t)(unsafe.SliceData(c)), ek.p, (*C.uint8_t)(unsafe.SliceData(m)))
	return key, c
}

func (dk *Mlkem768DecapKey) Drop() {
	C.mlkem768_drop_decapkey_handle(dk.p)
}

func (ek *Mlkem768EncapKey) Drop() {
	C.mlkem768_drop_encapkey_handle(ek.p)
}
