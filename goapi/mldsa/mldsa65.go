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

const PublicKeySize65 = 1952
const PrivateKeySize65 = 4032
const SignatureSize65 = 3309

type mldsa65PrivateKey struct {
	p unsafe.Pointer
}

type mldsa65PublicKey struct {
	p unsafe.Pointer
}

func newMldsa65PrivateKey(p unsafe.Pointer) *mldsa65PrivateKey {
	sk := &mldsa65PrivateKey{p}
	runtime.SetFinalizer(sk, func(sk *mldsa65PrivateKey) {
		C.mldsa65_drop_private_key_handle(sk.p)
	})
	return sk
}

func newMldsa65PublicKey(p unsafe.Pointer) *mldsa65PublicKey {
	pk := &mldsa65PublicKey{p}
	runtime.SetFinalizer(pk, func(pk *mldsa65PublicKey) {
		C.mldsa65_drop_public_key_handle(pk.p)
	})
	return pk
}

func Mldsa65KeyGen() *mldsa65PrivateKey {
	xi := make([]byte, 32)
	rand.Read(xi)
	p := C.mldsa65_generate_key_internal((*C.uint8_t)(unsafe.SliceData(xi)))
	return newMldsa65PrivateKey(p)
}

func (sk mldsa65PrivateKey) PublicKey() *mldsa65PublicKey {
	return newMldsa65PublicKey(C.mldsa65_public_key(sk.p))
}

func (sk mldsa65PrivateKey) Encode() {

}

func NewMldsa65PublicKey(encodedPk []byte) (*mldsa65PublicKey, error) {
	if len(encodedPk) != PublicKeySize65 {
		return nil, errors.New(fmt.Sprintf("MLDSA65 has public key size %d, but got %d", PublicKeySize65, len(encodedPk)))
	}
	p := C.mldsa65_import_public_key((*C.uint8_t)(unsafe.SliceData(encodedPk)))
	return newMldsa65PublicKey(p), nil
}

func NewMldsa65PrivateKey(encodedSk []byte) (*mldsa65PrivateKey, error) {
	if len(encodedSk) != PrivateKeySize65 {
		return nil, errors.New(fmt.Sprintf("MLDSA65 has private key size %d, but got %d", PrivateKeySize65, len(encodedSk)))
	}
	p := C.mldsa65_import_private_key((*C.uint8_t)(unsafe.SliceData(encodedSk)))
	return newMldsa65PrivateKey(p), nil
}

func (sk mldsa65PrivateKey) Sign(m []byte, rnd io.Reader) []byte {
	r := make([]byte, 32)
	sig := make([]byte, SignatureSize65)

	C.mldsa65_sign_internal((*C.uint8_t)(unsafe.SliceData(sig)), sk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m)), (*C.uint8_t)(unsafe.SliceData(r)))

	return sig
}

func (pk mldsa65PublicKey) Verify(sig []byte, m []byte) bool {
	return bool(C.mldsa65_verify_internal((*C.uint8_t)(unsafe.SliceData(sig)), pk.p, (*C.uint8_t)(unsafe.SliceData(m)), C.uintptr_t(len(m))))
}
