package mlkem

// #include "../../libs/opengm_pqc.h"
import "C"

import (
	"crypto/rand"
	"runtime"
	"unsafe"

	_ "github.com/opengm-libs/opengm_pqc/goapi"
)

const EncapKeySize1024 = 1568
const DecapKeySize1024 = 3168
const CipherSize1024 = 1568

type Mlkem1024DecapKey struct {
	p unsafe.Pointer
}

type Mlkem1024EncapKey struct {
	p unsafe.Pointer
}

func newMlkem1024DecapKey(p unsafe.Pointer) *Mlkem1024DecapKey {
	sk := &Mlkem1024DecapKey{p}
	runtime.SetFinalizer(sk, func(sk *Mlkem1024DecapKey) {
		sk.Drop()
	})
	return sk
}

func newMlkem1024EncapKey(p unsafe.Pointer) *Mlkem1024EncapKey {
	pk := &Mlkem1024EncapKey{p}
	runtime.SetFinalizer(pk, func(pk *Mlkem1024EncapKey) {
		pk.Drop()
	})
	return pk
}

func Mlkem1024KeyGen() *Mlkem1024DecapKey {
	d := make([]byte, 32)
	z := make([]byte, 32)

	rand.Read(d)
	rand.Read(z)

	return newMlkem1024DecapKey(C.mlkem1024_keygen_internal((*C.uint8_t)(unsafe.SliceData(d)), (*C.uint8_t)(unsafe.SliceData(z))))
}

func (dk Mlkem1024DecapKey) EncapKey() *Mlkem1024EncapKey {
	return newMlkem1024EncapKey(C.mlkem1024_encapkey(dk.p))
}

func (dk Mlkem1024DecapKey) Encode() []byte {
	b := make([]byte, DecapKeySize1024)
	C.mlkem1024_decapkey_encode((*C.uint8_t)(&b[0]), dk.p)
	return b
}

func (dk Mlkem1024DecapKey) Decap(c []byte) []byte {
	key := make([]byte, 32)
	C.mlkem1024_decap((*C.uint8_t)(&key[0]), (*C.uint8_t)(&c[0]), dk.p)
	return key
}

func (ek Mlkem1024EncapKey) Encode() []byte {
	b := make([]byte, EncapKeySize1024)
	C.mlkem1024_encapkey_encode((*C.uint8_t)(&b[0]), ek.p)
	return b
}

func (ek Mlkem1024EncapKey) Encap() ([]byte, []byte) {
	key := make([]byte, 32)
	c := make([]byte, CipherSize1024)
	m := make([]byte, 32)
	rand.Read(m)

	C.mlkem1024_encap_internal((*C.uint8_t)(&key[0]), (*C.uint8_t)(&c[0]), ek.p, (*C.uint8_t)(&m[0]))
	return key, c
}
func (dk *Mlkem1024DecapKey) Drop() {
	C.mlkem1024_drop_decapkey_handle(dk.p)
}

func (ek *Mlkem1024EncapKey) Drop() {
	C.mlkem1024_drop_encapkey_handle(ek.p)
}
