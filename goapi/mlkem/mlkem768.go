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

func NewMlkem768DecapKey(encodeKey []byte) (*Mlkem768DecapKey, error) {
	if len(encodeKey) != DecapKeySize768 {
		return nil, fmt.Errorf("encode decap key size wang %d, got %d", DecapKeySize768, len(encodeKey))
	}
	return newMlkem768DecapKey(C.mlkem768_decapkey_decode((*C.uint8_t)(unsafe.SliceData(encodeKey)))), nil
}

func NewMlkem768EncapKey(encodeKey []byte) (*Mlkem768EncapKey, error) {
	if len(encodeKey) != EncapKeySize768 {
		return nil, fmt.Errorf("encode decap key size wang %d, got %d", EncapKeySize768, len(encodeKey))
	}
	return newMlkem768EncapKey(C.mlkem768_encapkey_decode((*C.uint8_t)(unsafe.SliceData(encodeKey)))), nil
}

func Mlkem768KeyGenInternal(d, z []byte) (*Mlkem768DecapKey, error) {
	if len(d) != 32 || len(z) != 32 {
		return nil, fmt.Errorf("input d/z must have size 32")
	}
	return newMlkem768DecapKey(C.mlkem768_keygen_internal((*C.uint8_t)(unsafe.SliceData(d)), (*C.uint8_t)(unsafe.SliceData(z)))), nil
}
func Mlkem768KeyGen(rnd io.Reader) (*Mlkem768DecapKey, error) {
	d := make([]byte, 32)
	z := make([]byte, 32)

	if _, err := rnd.Read(d); err != nil {
		return nil, err
	}
	if _, err := rnd.Read(z); err != nil {
		return nil, err
	}
	return Mlkem768KeyGenInternal(d, z)
}

func (dk *Mlkem768DecapKey) EncapKey() *Mlkem768EncapKey {
	return newMlkem768EncapKey(C.mlkem768_encapkey(dk.p))
}

func (dk *Mlkem768DecapKey) Encode() []byte {
	b := make([]byte, DecapKeySize768)
	C.mlkem768_decapkey_encode((*C.uint8_t)(unsafe.SliceData(b)), dk.p)
	return b
}

func (dk *Mlkem768DecapKey) Decap(c []byte) ([]byte, error) {
	if len(c) != CipherSize768 {
		return nil, fmt.Errorf("mlkem512 want cipher size %d, got %d", CipherSize512, len(c))
	}
	key := make([]byte, 32)
	C.mlkem768_decap((*C.uint8_t)(unsafe.SliceData(key)), (*C.uint8_t)(unsafe.SliceData(c)), dk.p)
	return key, nil
}

func (ek *Mlkem768EncapKey) Encode() []byte {
	b := make([]byte, EncapKeySize768)
	C.mlkem768_encapkey_encode((*C.uint8_t)(unsafe.SliceData(b)), ek.p)
	return b
}

func (ek *Mlkem768EncapKey) Encap() ([]byte, []byte) {
	key := make([]byte, 32)
	c := make([]byte, CipherSize768)
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
