package mldsa_tpc

// #include "../libs/opengm_pqc.h"
import "C"
import (
	"fmt"
	"io"
	"runtime"
	"unsafe"

	_ "github.com/opengm-libs/opengm_pqc/goapi"
	"github.com/opengm-libs/opengm_pqc/goapi/mldsa"
)

const k = 6
const l = 5

const KeygenClientToServerDataLen65 = 32 + 1024*k

const KeygenServerToClientDataLen65 = 1024*k + 64

const SignClientToServerDataLen65 = 64 + 1024*k

const SignServerToClientDataLen65 = 1024 * (2*k + l)

type ClientKeyGenCtx65 struct {
	p unsafe.Pointer
}

type ClientKey65 struct {
	p unsafe.Pointer
}

type ServerKey65 struct {
	p unsafe.Pointer
}

type ClientSignCtx65 struct {
	p unsafe.Pointer
}

func newClientKey65(p unsafe.Pointer) *ClientKey65 {
	sk := &ClientKey65{p}
	runtime.SetFinalizer(sk, func(sk *ClientKey65) {
		sk.Drop()
	})
	return sk
}

func newServerKey65(p unsafe.Pointer) *ServerKey65 {
	sk := &ServerKey65{p}
	runtime.SetFinalizer(sk, func(sk *ServerKey65) {
		sk.Drop()
	})
	return sk
}

func newClientSignCtx65(p unsafe.Pointer) *ClientSignCtx65 {
	sk := &ClientSignCtx65{p}
	runtime.SetFinalizer(sk, func(sk *ClientSignCtx65) {
		sk.Drop()
	})
	return sk
}

func newClientKeyGenCtx65(p unsafe.Pointer) *ClientKeyGenCtx65 {
	sk := &ClientKeyGenCtx65{p}
	runtime.SetFinalizer(sk, func(sk *ClientKeyGenCtx65) {
		sk.Drop()
	})
	return sk
}

func NewClientKey65(skBytes []byte) (*ClientKey65, error) {
	if len(skBytes) != mldsa.PrivateKeySize65 {
		return nil, fmt.Errorf("Client key bytes want %d, got %d", mldsa.PrivateKeySize65, len(skBytes))
	}
	p := C.mldsa65_tpc_import_client_key((*C.uint8_t)(unsafe.SliceData(skBytes)))
	if p != nil {
		return newClientKey65(p), nil
	}
	return nil, fmt.Errorf("NewClientKey65 error")

}

func NewServerKey65(skBytes []byte) (*ServerKey65, error) {
	if len(skBytes) != mldsa.PrivateKeySize65 {
		return nil, fmt.Errorf("Client key bytes want %d, got %d", mldsa.PrivateKeySize65, len(skBytes))
	}
	p := C.mldsa65_tpc_import_server_key((*C.uint8_t)(unsafe.SliceData(skBytes)))
	if p != nil {
		return newServerKey65(p), nil
	}
	return nil, fmt.Errorf("NewServerKey65 error")

}

func (sk *ClientKey65) Drop() {
	C.mldsa65_tpc_drop_client_key_handle(sk.p)
}

func (sk *ServerKey65) Drop() {
	C.mldsa65_tpc_drop_server_key_handle(sk.p)
}

func (sk *ClientKeyGenCtx65) Drop() {
	C.mldsa65_tpc_drop_client_keygen_ctx_handle(sk.p)
}

func (sk *ClientSignCtx65) Drop() {
	C.mldsa65_tpc_drop_client_sign_ctx_handle(sk.p)
}

// void mldsa65_tpc_client_key_encode(uint8_t *sk_out, uint8_t *pk_out, void *sk_handle);
func (sk *ClientKey65) Encode() (skBytes []byte, pkBytes []byte) {
	skBytes = make([]byte, mldsa.PrivateKeySize65)
	pkBytes = make([]byte, mldsa.PublicKeySize65)
	C.mldsa65_tpc_client_key_encode(
		(*C.uint8_t)(unsafe.SliceData(skBytes)),
		(*C.uint8_t)(unsafe.SliceData(pkBytes)),
		sk.p,
	)
	return skBytes, pkBytes
}

func (sk *ServerKey65) Encode() (skBytes []byte, pkBytes []byte) {
	skBytes = make([]byte, mldsa.PrivateKeySize65)
	pkBytes = make([]byte, mldsa.PublicKeySize65)
	C.mldsa65_tpc_server_key_encode(
		(*C.uint8_t)(unsafe.SliceData(skBytes)),
		(*C.uint8_t)(unsafe.SliceData(pkBytes)),
		sk.p,
	)
	return skBytes, pkBytes
}

func Mldsa65Tpc_ClientKeygen0(rnd io.Reader) (*ClientKeyGenCtx65, []byte, error) {
	toServer := make([]byte, KeygenClientToServerDataLen65)
	xi := toServer[:32]

	r := make([]byte, 64)
	if _, err := rnd.Read(xi); err != nil {
		return nil, nil, err
	}
	if _, err := rnd.Read(r); err != nil {
		return nil, nil, err
	}

	p := C.mldsa65_tpc_client_keygen0_internal(
		(*C.uint8_t)(unsafe.SliceData(xi)),
		(*C.uint8_t)(unsafe.SliceData(r)),
		(*C.uint8_t)(unsafe.SliceData(toServer[32:])),
	)
	if p != nil {
		return newClientKeyGenCtx65(p), toServer, nil
	}
	return nil, nil, fmt.Errorf("client keygen phase 0 error")
}

// return client key handle
func Mldsa65Tpc_ClientKeygen1(ctx *ClientKeyGenCtx65, fromServer []byte) (*ClientKey65, error) {
	if len(fromServer) != KeygenServerToClientDataLen65 {
		return nil, fmt.Errorf("server data error")
	}
	p := C.mldsa65_tpc_client_keygen1_internal(ctx.p, (*C.uint8_t)(unsafe.SliceData(fromServer)))
	if p != nil {
		return newClientKey65(p), nil
	}
	return nil, fmt.Errorf("client keygen phase 1 error")
}

func Mldsa65Tpc_ServerKeyGen(rnd io.Reader, fromClient []byte) (*ServerKey65, []byte, error) {
	if len(fromClient) != KeygenClientToServerDataLen65 {
		return nil, nil, fmt.Errorf("received client data error")
	}
	xi := fromClient[:32]
	r := make([]byte, 64)
	if _, err := rnd.Read(r); err != nil {
		return nil, nil, err
	}
	toClient := make([]byte, KeygenServerToClientDataLen65)

	p := C.mldsa65_tpc_server_keygen_internal(
		(*C.uint8_t)(unsafe.SliceData(xi)),
		(*C.uint8_t)(unsafe.SliceData(r)),
		(*C.uint8_t)(unsafe.SliceData(fromClient[32:])),
		(*C.uint8_t)(unsafe.SliceData(toClient)),
	)
	if p != nil {
		return newServerKey65(p), toClient, nil
	}
	return nil, nil, fmt.Errorf("server keygen error")
}

// void *mldsa65_tpc_client_sign0_internal(uint8_t *to_server, void *client_key_handle, const uint8_t *client_rnd, const uint8_t *m, uintptr_t mlen);

func Mldsa65Tpc_ClientSign0(clientKey *ClientKey65, m []byte, rnd io.Reader) (*ClientSignCtx65, []byte, error) {
	to_server := make([]byte, SignClientToServerDataLen65)
	r := make([]byte, 32)
	if _, err := rnd.Read(r); err != nil {
		return nil, nil, err
	}
	p := C.mldsa65_tpc_client_sign0_internal(
		(*C.uint8_t)(unsafe.SliceData(to_server)),
		clientKey.p,
		(*C.uint8_t)(unsafe.SliceData(r)),
		(*C.uint8_t)(unsafe.SliceData(m)),
		C.uintptr_t(len(m)),
	)

	if p != nil {
		return newClientSignCtx65(p), to_server, nil
	}
	return nil, nil, fmt.Errorf("ClientSign0 error")
}

// bool mldsa65_tpc_client_sign1(void *ctx, void *client_key_handle, uint8_t *signature, const uint8_t *from_server);
func Mldsa65Tpc_ClientSign1(ctx *ClientSignCtx65, clientKey *ClientKey65, serverData []byte) ([]byte, error) {
	signature := make([]byte, mldsa.SignatureSize65)
	ok := C.mldsa65_tpc_client_sign1(
		ctx.p,
		clientKey.p,
		(*C.uint8_t)(unsafe.SliceData(signature)),
		(*C.uint8_t)(unsafe.SliceData(serverData)),
	)

	if ok {
		return signature, nil
	}
	return nil, fmt.Errorf("ClientSign1 error")
}

// bool mldsa65_tpc_server_sign_internal(uint8_t *to_client, void *server_key_handle, const uint8_t *server_rnd, const uint8_t *m, uintptr_t mlen, const uint8_t *from_client);
func Mldsa65Tpc_ServerSign(serverKey *ServerKey65, m []byte, clientData []byte, rnd io.Reader) ([]byte, error) {
	serverData := make([]byte, SignServerToClientDataLen65)
	r := make([]byte, 32)
	if _, err := rnd.Read(r); err != nil {
		return nil, err
	}
	ok := C.mldsa65_tpc_server_sign_internal(
		(*C.uint8_t)(unsafe.SliceData(serverData)),
		serverKey.p,
		(*C.uint8_t)(unsafe.SliceData(r)),
		(*C.uint8_t)(unsafe.SliceData(m)),
		C.uintptr_t(len(m)),
		(*C.uint8_t)(unsafe.SliceData(clientData)),
	)
	if ok {
		return serverData, nil
	}
	return nil, fmt.Errorf("ServerSign error")
}
