package mldsa

// #include "../../libs/opengm_pqc.h"
import "C"

import (
	"fmt"
	"io"
	"runtime"
	"unsafe"

	_ "github.com/opengm-libs/opengm_pqc/goapi"
)

const PublicKeySize44 = 1312
const PrivateKeySize44 = 2560
const SignatureSize44 = 2420

type Mldsa44PrivateKey struct {
	p unsafe.Pointer
}

type Mldsa44PublicKey struct {
	p unsafe.Pointer
}

func newMldsa44PrivateKey(p unsafe.Pointer) *Mldsa44PrivateKey {
	sk := &Mldsa44PrivateKey{p}
	runtime.SetFinalizer(sk, func(sk *Mldsa44PrivateKey) {
		sk.Drop()
	})
	return sk
}

func newMldsa44PublicKey(p unsafe.Pointer) *Mldsa44PublicKey {
	pk := &Mldsa44PublicKey{p}
	runtime.SetFinalizer(pk, func(pk *Mldsa44PublicKey) {
		pk.Drop()
	})
	return pk
}

func Mldsa44KeyGen(rnd io.Reader) (*Mldsa44PrivateKey, error) {
	xi := make([]byte, 32)
	if _, err := rnd.Read(xi); err != nil {
		return nil, err
	}
	return Mldsa44KeyGenInternal(xi)
}

// Mldsa44KeyGenInternal generate key internal.
func Mldsa44KeyGenInternal(xi []byte) (*Mldsa44PrivateKey, error) {
	if len(xi) != 32 {
		return nil, fmt.Errorf("seed length want 32, got %d", len(xi))
	}
	p := C.mldsa44_generate_key_internal((*C.uint8_t)(unsafe.SliceData(xi)))
	return newMldsa44PrivateKey(p), nil
}

func (sk Mldsa44PrivateKey) PublicKey() *Mldsa44PublicKey {
	return newMldsa44PublicKey(C.mldsa44_public_key(sk.p))
}

func NewMldsa44PublicKey(encodedPk []byte) (*Mldsa44PublicKey, error) {
	if len(encodedPk) != PublicKeySize44 {
		return nil, fmt.Errorf("MLDSA44 has public key size %d, but got %d", PublicKeySize44, len(encodedPk))
	}
	p := C.mldsa44_import_public_key((*C.uint8_t)(unsafe.SliceData(encodedPk)))
	return newMldsa44PublicKey(p), nil
}

func NewMldsa44PrivateKey(encodedSk []byte) (*Mldsa44PrivateKey, error) {
	if len(encodedSk) != PrivateKeySize44 {
		return nil, fmt.Errorf("MLDSA44 has private key size %d, but got %d", PrivateKeySize44, len(encodedSk))
	}
	p := C.mldsa44_import_private_key((*C.uint8_t)(unsafe.SliceData(encodedSk)))
	return newMldsa44PrivateKey(p), nil
}

func (sk Mldsa44PrivateKey) Sign(m []byte, rnd io.Reader) ([]byte, error) {
	r := make([]byte, 32)
	if _, err := rnd.Read(r); err != nil {
		return nil, err
	}
	sig := make([]byte, SignatureSize44)

	C.mldsa44_sign_internal((*C.uint8_t)(unsafe.SliceData(sig)), sk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m)), (*C.uint8_t)(unsafe.SliceData(r)))

	return sig, nil
}

func (pk Mldsa44PublicKey) Verify(sig []byte, m []byte) bool {
	return bool(C.mldsa44_verify_internal((*C.uint8_t)(unsafe.SliceData(sig)), pk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m))))
}
func (pk Mldsa44PublicKey) Drop() {
	C.mldsa44_drop_public_key_handle(pk.p)
}

func (pk Mldsa44PrivateKey) Drop() {
	C.mldsa44_drop_private_key_handle(pk.p)
}

func (sk Mldsa44PrivateKey) Encode() []byte {
	b := make([]byte, PrivateKeySize44)
	C.mldsa44_private_key_encode((*C.uint8_t)(unsafe.SliceData(b)), sk.p)
	return b
}

func (pk Mldsa44PublicKey) Encode() []byte {
	b := make([]byte, PublicKeySize44)
	C.mldsa44_public_key_encode((*C.uint8_t)(unsafe.SliceData(b)), pk.p)
	return b
}
