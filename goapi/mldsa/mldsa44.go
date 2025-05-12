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

const PublicKeySize44 = 1312
const PrivateKeySize44 = 2560
const SignatureSize44 = 2420

type mldsa44PrivateKey struct {
	p unsafe.Pointer
}

type mldsa44PublicKey struct {
	p unsafe.Pointer
}

func newMldsa44PrivateKey(p unsafe.Pointer) *mldsa44PrivateKey {
	sk := &mldsa44PrivateKey{p}
	runtime.SetFinalizer(sk, func(sk *mldsa44PrivateKey) {
		C.mldsa44_drop_private_key_handle(sk.p)
	})
	return sk
}

func newMldsa44PublicKey(p unsafe.Pointer) *mldsa44PublicKey {
	pk := &mldsa44PublicKey{p}
	runtime.SetFinalizer(pk, func(pk *mldsa44PublicKey) {
		C.mldsa44_drop_public_key_handle(pk.p)
	})
	return pk
}

func Mldsa44KeyGen() *mldsa44PrivateKey {
	xi := make([]byte, 32)
	rand.Read(xi)
	p := C.mldsa44_generate_key_internal((*C.uint8_t)(unsafe.SliceData(xi)))
	return newMldsa44PrivateKey(p)
}

func (sk mldsa44PrivateKey) PublicKey() *mldsa44PublicKey {
	return newMldsa44PublicKey(C.mldsa44_public_key(sk.p))
}

func NewMldsa44PublicKey(encodedPk []byte) (*mldsa44PublicKey, error) {
	if len(encodedPk) != PublicKeySize44 {
		return nil, errors.New(fmt.Sprintf("MLDSA44 has public key size %d, but got %d", PublicKeySize44, len(encodedPk)))
	}
	p := C.mldsa44_import_public_key((*C.uint8_t)(unsafe.SliceData(encodedPk)))
	return newMldsa44PublicKey(p), nil
}

func NewMldsa44PrivateKey(encodedSk []byte) (*mldsa44PrivateKey, error) {
	if len(encodedSk) != PrivateKeySize44 {
		return nil, errors.New(fmt.Sprintf("MLDSA44 has private key size %d, but got %d", PrivateKeySize44, len(encodedSk)))
	}
	p := C.mldsa44_import_private_key((*C.uint8_t)(unsafe.SliceData(encodedSk)))
	return newMldsa44PrivateKey(p), nil
}

func (sk mldsa44PrivateKey) Sign(m []byte, rnd io.Reader) []byte {
	r := make([]byte, 32)
	sig := make([]byte, SignatureSize44)

	C.mldsa44_sign_internal((*C.uint8_t)(unsafe.SliceData(sig)), sk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m)), (*C.uint8_t)(unsafe.SliceData(r)))

	return sig
}

func (pk mldsa44PublicKey) Verify(sig []byte, m []byte) bool {
	return bool(C.mldsa44_verify_internal((*C.uint8_t)(unsafe.SliceData(sig)), pk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m))))
}
