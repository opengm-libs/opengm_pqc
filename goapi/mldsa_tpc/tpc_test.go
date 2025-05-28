package mldsa_tpc

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/opengm-libs/opengm_pqc/goapi/mldsa"
)

// 循环次数-1: 概率
// 0: 0.2929
// 1: 0.2072
// 2: 0.1464
// 3: 0.1035
// 4: 0.0732
// 5: 0.0519
// 6: 0.0365
// 7: 0.0258
// 8: 0.0183
// 9: 0.0129
// 10: 0.0092
// 11: 0.0065
// 12: 0.0046
// 13: 0.0032
// 14: 0.0023
// 15: 0.0016
// 16: 0.0011
// 17: 0.0008
// 18: 0.0006
// 19: 0.0004
// 20: 0.0003
// 21: 0.0002
// 22: 0.0001
// 23: 0.0001
// 24: 0.0001
// 25: 0.0001

func TestKeygen(t *testing.T) {
	keygenCtx, toServer, err := Mldsa65Tpc_ClientKeygen0(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, toClient, err := Mldsa65Tpc_ServerKeyGen(rand.Reader, toServer)
	if err != nil {
		t.Fatal(err)
	}

	clientKey, err := Mldsa65Tpc_ClientKeygen1(keygenCtx, toClient)
	if err != nil {
		t.Fatal(err)
	}

	_, clientPublicKey := clientKey.Encode()
	_, serverPublicKey := serverKey.Encode()
	if bytes.Compare(clientPublicKey, serverPublicKey) != 0 {
		t.Fatal()
	}

	m := make([]byte, 32)
	rand.Read(m)
	var sig []byte
	counts := make([]int, 100)
	total := 1000
	for i := 0; i < total; i++ {
		count := 0
		for {
			signCtx, clientData, err := Mldsa65Tpc_ClientSign0(clientKey, m, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			serverData, err := Mldsa65Tpc_ServerSign(serverKey, m, clientData, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			sig, err = Mldsa65Tpc_ClientSign1(signCtx, clientKey, serverData)
			if err != nil {
				count++
				continue
			}
			break
		}
		publicKey, err := mldsa.NewMldsa65PublicKey(clientPublicKey)
		if err != nil {
			t.Fatal(err)
		}

		if !publicKey.Verify(sig, m) {
			t.Fatal("verify failed")
		}
		counts[count]++
	}
	for i := 0; i < len(counts); i++ {
		fmt.Printf("%d: %.4f\n", i, float64(counts[i])/float64(total))
	}
}
