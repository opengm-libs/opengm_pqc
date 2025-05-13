package mlkem

// #include "../../libs/opengm_pqc.h"
import "C"

import (
	"crypto/rand"
	"runtime"
	"unsafe"

	_ "github.com/opengm-libs/opengm_pqc/goapi"
)

const EncapKeySize512 = 800
const DecapKeySize512 = 1632
const CipherSize512 = 768

type Mlkem512DecapKey struct {
	p unsafe.Pointer
}

type Mlkem512EncapKey struct {
	p unsafe.Pointer
}

func newMlkem512DecapKey(p unsafe.Pointer) *Mlkem512DecapKey {
	dk := &Mlkem512DecapKey{p}
	runtime.SetFinalizer(dk, func(dk *Mlkem512DecapKey) {
		dk.Drop()
	})
	return dk
}

func newMlkem512EncapKey(p unsafe.Pointer) *Mlkem512EncapKey {
	ek := &Mlkem512EncapKey{p}
	runtime.SetFinalizer(ek, func(ek *Mlkem512EncapKey) {
		ek.Drop()
	})
	return ek
}

func Mlkem512KeyGen() *Mlkem512DecapKey {
	d := make([]byte, 32)
	z := make([]byte, 32)

	rand.Read(d)
	rand.Read(z)

	return newMlkem512DecapKey(C.mlkem512_keygen_internal((*C.uint8_t)(unsafe.SliceData(d)), (*C.uint8_t)(unsafe.SliceData(z))))
}

func (dk *Mlkem512DecapKey) EncapKey() *Mlkem512EncapKey {
	return newMlkem512EncapKey(C.mlkem512_encapkey(dk.p))
}

func (dk *Mlkem512DecapKey) Encode() []byte {
	b := make([]byte, DecapKeySize1024)
	C.mlkem512_decapkey_encode((*C.uint8_t)(&b[0]), dk.p)
	return b
}

func (dk *Mlkem512DecapKey) Decap(c []byte) []byte {
	key := make([]byte, 32)
	C.mlkem512_decap((*C.uint8_t)(&key[0]), (*C.uint8_t)(&c[0]), dk.p)
	return key
}

func (ek *Mlkem512EncapKey) Encode() []byte {
	b := make([]byte, EncapKeySize1024)
	C.mlkem512_encapkey_encode((*C.uint8_t)(&b[0]), ek.p)
	return b
}

func (ek *Mlkem512EncapKey) Encap() ([]byte, []byte) {
	key := make([]byte, 32)
	c := make([]byte, CipherSize1024)
	m := make([]byte, 32)
	rand.Read(m)

	C.mlkem512_encap_internal((*C.uint8_t)(&key[0]), (*C.uint8_t)(&c[0]), ek.p, (*C.uint8_t)(&m[0]))
	return key, c
}
func (dk *Mlkem512DecapKey) Drop() {
	C.mlkem512_drop_decapkey_handle(dk.p)
}

func (ek *Mlkem512EncapKey) Drop() {
	C.mlkem512_drop_encapkey_handle(ek.p)
}
