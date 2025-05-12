package mlkem

// #include "../../libs/opengm_pqc.h"
import "C"

import (
	"crypto/rand"
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

func Mlkem768KeyGen() *Mlkem768DecapKey {
	d := make([]byte, 32)
	z := make([]byte, 32)

	rand.Read(d)
	rand.Read(z)

	return &Mlkem768DecapKey{
		p: C.mlkem768_keygen_internal((*C.uint8_t)(unsafe.SliceData(d)), (*C.uint8_t)(unsafe.SliceData(z))),
	}
}

func (dk *Mlkem768DecapKey) EncapKey() *Mlkem768EncapKey {
	return &Mlkem768EncapKey{
		p: C.mlkem768_encapkey(dk.p),
	}
}

func (dk *Mlkem768DecapKey) Encode() []byte {
	b := make([]byte, DecapKeySize1024)
	C.mlkem768_decapkey_encode((*C.uint8_t)(&b[0]), dk.p)
	return b
}

func (dk *Mlkem768DecapKey) Decap(c []byte) []byte {
	key := make([]byte, 32)
	C.mlkem768_decap((*C.uint8_t)(&key[0]), (*C.uint8_t)(&c[0]), dk.p)
	return key
}

func (ek *Mlkem768EncapKey) Encode() []byte {
	b := make([]byte, EncapKeySize1024)
	C.mlkem768_encapkey_encode((*C.uint8_t)(&b[0]), ek.p)
	return b
}

func (ek *Mlkem768EncapKey) Encap() ([]byte, []byte) {
	key := make([]byte, 32)
	c := make([]byte, CipherSize1024)
	m := make([]byte, 32)
	rand.Read(m)

	C.mlkem768_encap_internal((*C.uint8_t)(&key[0]), (*C.uint8_t)(&c[0]), ek.p, (*C.uint8_t)(&m[0]))
	return key, c
}
