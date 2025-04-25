package mlkem

// #include "../../libs/opengm_pqc.h"
import "C"

import (
	"crypto/rand"

	_ "github.com/opengm-libs/opengm_pqc/goapi"
)

const EncapKeySize768 = 1184
const DecapKeySize768 = 2400
const CipherSize768 = 1088

const k768 = 3

// unencoded decapsulation key bytes
const DecapKeySizeUnencoded768 = (2*k768+k768*k768)*512 + 96

// unencoded encapsulation key bytes
const EncapKeySizeUnencoded768 = (k768+k768*k768)*512 + 64

type Mlkem768DecapKey struct {
	raw []byte
	s   []byte
	z   []byte
	ek  Mlkem768EncapKey
}

type Mlkem768EncapKey struct {
	ek []byte
}

func Mlkem768KeyGen() *Mlkem768DecapKey {
	buf := make([]byte, DecapKeySizeUnencoded768)
	d := make([]byte, 32)
	z := make([]byte, 32)

	rand.Read(d)
	rand.Read(z)
	C.mlkem768_keygen_internal((*C.uint8_t)(&buf[0]), (*C.uint8_t)(&d[0]), (*C.uint8_t)(&z[0]))

	return &Mlkem768DecapKey{
		raw: buf,
		s:   buf[:512*k768],
		z:   buf[512*k768 : 512*k768+32],
		ek: Mlkem768EncapKey{
			ek: buf[512*k768+32:],
		},
	}
}

func (dk *Mlkem768DecapKey) EncapKey() *Mlkem768EncapKey {
	return &dk.ek
}

func (dk *Mlkem768DecapKey) Encode() []byte {
	b := make([]byte, DecapKeySize768)
	C.mlkem768_decapkey_encode((*C.uint8_t)(&b[0]), (*C.uint8_t)(&dk.raw[0]))
	return b
}

func (dk *Mlkem768DecapKey) Decap(c []byte) []byte {
	key := make([]byte, 32)
	C.mlkem768_decap((*C.uint8_t)(&key[0]), (*C.uint8_t)(&c[0]), (*C.uint8_t)(&dk.raw[0]))
	return key
}

func (ek *Mlkem768EncapKey) Encode() []byte {
	b := make([]byte, EncapKeySize768)
	C.mlkem768_encapkey_encode((*C.uint8_t)(&b[0]), (*C.uint8_t)(&ek.ek[0]))
	return b
}

func (ek *Mlkem768EncapKey) Encap() ([]byte, []byte) {
	key := make([]byte, 32)
	c := make([]byte, 1088)
	m := make([]byte, 32)
	rand.Read(m)

	C.mlkem768_encap_internal((*C.uint8_t)(&key[0]), (*C.uint8_t)(&c[0]), (*C.uint8_t)(&ek.ek[0]), (*C.uint8_t)(&m[0]))
	return key, c
}
