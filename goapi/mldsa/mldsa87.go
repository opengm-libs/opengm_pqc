package mldsa

// #include "../../libs/opengm_pqc.h"
import "C"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"

	_ "github.com/opengm-libs/opengm_pqc/goapi"
)

const PublicKeySize87 = 2592
const PrivateKeySize87 = 4896
const SignatureSize87 = 4627

type mldsa87PrivateKey struct {
	p unsafe.Pointer
}

type mldsa87PublicKey struct {
	p unsafe.Pointer
}

func newMldsa87PrivateKey(p unsafe.Pointer) *mldsa87PrivateKey {
	sk := &mldsa87PrivateKey{p}
	runtime.SetFinalizer(sk, func(sk *mldsa87PrivateKey) {
		C.mldsa87_drop_private_key_handle(sk.p)
	})
	return sk
}

func newMldsa87PublicKey(p unsafe.Pointer) *mldsa87PublicKey {
	pk := &mldsa87PublicKey{p}
	runtime.SetFinalizer(pk, func(pk *mldsa87PublicKey) {
		C.mldsa87_drop_public_key_handle(pk.p)
	})
	return pk
}

func Mldsa87KeyGen() *mldsa87PrivateKey {
	xi := make([]byte, 32)
	rand.Read(xi)
	p := C.mldsa87_generate_key_internal((*C.uint8_t)(unsafe.SliceData(xi)))
	return newMldsa87PrivateKey(p)
}

func (sk mldsa87PrivateKey) PublicKey() *mldsa87PublicKey {
	return newMldsa87PublicKey(C.mldsa87_public_key(sk.p))
}

func NewMldsa87PublicKey(encodedPk []byte) (*mldsa87PublicKey, error) {
	if len(encodedPk) != PublicKeySize87 {
		return nil, errors.New(fmt.Sprintf("MLDSA87 has public key size %d, but got %d", PublicKeySize87, len(encodedPk)))
	}
	p := C.mldsa87_import_public_key((*C.uint8_t)(unsafe.SliceData(encodedPk)))
	return newMldsa87PublicKey(p), nil
}

func NewMldsa87PrivateKey(encodedSk []byte) (*mldsa87PrivateKey, error) {
	if len(encodedSk) != PrivateKeySize87 {
		return nil, errors.New(fmt.Sprintf("MLDSA87 has private key size %d, but got %d", PrivateKeySize87, len(encodedSk)))
	}
	p := C.mldsa87_import_private_key((*C.uint8_t)(unsafe.SliceData(encodedSk)))
	return newMldsa87PrivateKey(p), nil
}

func (sk mldsa87PrivateKey) Sign(m []byte, rnd io.Reader) []byte {
	r := make([]byte, 32)
	sig := make([]byte, SignatureSize87)

	C.mldsa87_sign_internal((*C.uint8_t)(unsafe.SliceData(sig)), sk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m)), (*C.uint8_t)(unsafe.SliceData(r)))

	return sig
}

func (pk mldsa87PublicKey) Verify(sig []byte, m []byte) bool {
	return bool(C.mldsa87_verify_internal((*C.uint8_t)(unsafe.SliceData(sig)), pk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m))))
}
