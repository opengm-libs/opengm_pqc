package mlkem

// #include "../../libs/opengm_pqc.h"
import "C"

import (
	"crypto/rand"
	"fmt"
	"io"
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

func NewMlkem512DecapKey(encodeKey []byte) (*Mlkem512DecapKey, error) {
	if len(encodeKey) != DecapKeySize512 {
		return nil, fmt.Errorf("encode decap key size wang %d, got %d", DecapKeySize512, len(encodeKey))
	}
	return newMlkem512DecapKey(C.mlkem512_decapkey_decode((*C.uint8_t)(unsafe.SliceData(encodeKey)))), nil
}

func NewMlkem512EncapKey(encodeKey []byte) (*Mlkem512EncapKey, error) {
	if len(encodeKey) != EncapKeySize512 {
		return nil, fmt.Errorf("encode decap key size wang %d, got %d", EncapKeySize512, len(encodeKey))
	}
	return newMlkem512EncapKey(C.mlkem512_encapkey_decode((*C.uint8_t)(unsafe.SliceData(encodeKey)))), nil
}

func Mlkem512KeyGenInternal(d, z []byte) (*Mlkem512DecapKey, error) {
	if len(d) != 32 || len(z) != 32 {
		return nil, fmt.Errorf("input d/z must have size 32")
	}
	return newMlkem512DecapKey(C.mlkem512_keygen_internal((*C.uint8_t)(unsafe.SliceData(d)), (*C.uint8_t)(unsafe.SliceData(z)))), nil
}
func Mlkem512KeyGen(rnd io.Reader) (*Mlkem512DecapKey, error) {
	d := make([]byte, 32)
	z := make([]byte, 32)

	if _, err := rnd.Read(d); err != nil {
		return nil, err
	}
	if _, err := rnd.Read(z); err != nil {
		return nil, err
	}
	return Mlkem512KeyGenInternal(d, z)
}

func (dk *Mlkem512DecapKey) EncapKey() *Mlkem512EncapKey {
	return newMlkem512EncapKey(C.mlkem512_encapkey(dk.p))
}

func (dk *Mlkem512DecapKey) Encode() []byte {
	b := make([]byte, DecapKeySize512)
	C.mlkem512_decapkey_encode((*C.uint8_t)(&b[0]), dk.p)
	return b
}

func (dk *Mlkem512DecapKey) Decap(c []byte) ([]byte, error) {
	if len(c) != CipherSize512 {
		return nil, fmt.Errorf("mlkem512 want cipher size %d, got %d", CipherSize512, len(c))
	}
	key := make([]byte, 32)
	C.mlkem512_decap((*C.uint8_t)(&key[0]), (*C.uint8_t)(&c[0]), dk.p)
	return key, nil
}

func (ek *Mlkem512EncapKey) Encode() []byte {
	b := make([]byte, EncapKeySize512)
	C.mlkem512_encapkey_encode((*C.uint8_t)(&b[0]), ek.p)
	return b
}

func (ek *Mlkem512EncapKey) Encap() ([]byte, []byte) {
	key := make([]byte, 32)
	c := make([]byte, CipherSize512)
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
