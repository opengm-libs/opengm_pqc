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

const PublicKeySize87 = 2592
const PrivateKeySize87 = 4896
const SignatureSize87 = 4627

type Mldsa87PrivateKey struct {
	p unsafe.Pointer
}

type Mldsa87PublicKey struct {
	p unsafe.Pointer
}

func newMldsa87PrivateKey(p unsafe.Pointer) *Mldsa87PrivateKey {
	sk := &Mldsa87PrivateKey{p}
	runtime.SetFinalizer(sk, func(sk *Mldsa87PrivateKey) {
		sk.Drop()
	})
	return sk
}

func newMldsa87PublicKey(p unsafe.Pointer) *Mldsa87PublicKey {
	pk := &Mldsa87PublicKey{p}
	runtime.SetFinalizer(pk, func(pk *Mldsa87PublicKey) {
		pk.Drop()
	})
	return pk
}

func Mldsa87KeyGen(rnd io.Reader) (*Mldsa87PrivateKey, error) {
	xi := make([]byte, 32)
	if _, err := rnd.Read(xi); err != nil {
		return nil, err
	}
	return Mldsa87KeyGenInternal(xi)
}

// Mldsa87KeyGenInternal generate key internal.
func Mldsa87KeyGenInternal(xi []byte) (*Mldsa87PrivateKey, error) {
	if len(xi) != 32 {
		return nil, fmt.Errorf("seed length want 32, got %d", len(xi))
	}
	p := C.mldsa87_generate_key_internal((*C.uint8_t)(unsafe.SliceData(xi)))
	return newMldsa87PrivateKey(p), nil
}

func (sk Mldsa87PrivateKey) PublicKey() *Mldsa87PublicKey {
	return newMldsa87PublicKey(C.mldsa87_public_key(sk.p))
}

func NewMldsa87PublicKey(encodedPk []byte) (*Mldsa87PublicKey, error) {
	if len(encodedPk) != PublicKeySize87 {
		return nil, fmt.Errorf("MLDSA87 has public key size %d, but got %d", PublicKeySize87, len(encodedPk))
	}
	p := C.mldsa87_import_public_key((*C.uint8_t)(unsafe.SliceData(encodedPk)))
	return newMldsa87PublicKey(p), nil
}

func NewMldsa87PrivateKey(encodedSk []byte) (*Mldsa87PrivateKey, error) {
	if len(encodedSk) != PrivateKeySize87 {
		return nil, fmt.Errorf("MLDSA87 has private key size %d, but got %d", PrivateKeySize87, len(encodedSk))
	}
	p := C.mldsa87_import_private_key((*C.uint8_t)(unsafe.SliceData(encodedSk)))
	return newMldsa87PrivateKey(p), nil
}

func (sk Mldsa87PrivateKey) Sign(m []byte, rnd io.Reader) ([]byte, error) {
	r := make([]byte, 32)
	if _, err := rnd.Read(r); err != nil {
		return nil, err
	}
	sig := make([]byte, SignatureSize87)

	C.mldsa87_sign_internal((*C.uint8_t)(unsafe.SliceData(sig)), sk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m)), (*C.uint8_t)(unsafe.SliceData(r)))

	return sig, nil
}

func (pk Mldsa87PublicKey) Verify(sig []byte, m []byte) bool {
	return bool(C.mldsa87_verify_internal((*C.uint8_t)(unsafe.SliceData(sig)), pk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m))))
}
func (pk Mldsa87PublicKey) Drop() {
	C.mldsa87_drop_public_key_handle(pk.p)
}

func (pk Mldsa87PrivateKey) Drop() {
	C.mldsa87_drop_private_key_handle(pk.p)
}

func (sk Mldsa87PrivateKey) Encode() []byte {
	b := make([]byte, PrivateKeySize87)
	C.mldsa87_private_key_encode((*C.uint8_t)(unsafe.SliceData(b)), sk.p)
	return b
}

func (pk Mldsa87PublicKey) Encode() []byte {
	b := make([]byte, PublicKeySize87)
	C.mldsa87_public_key_encode((*C.uint8_t)(unsafe.SliceData(b)), pk.p)
	return b
}
