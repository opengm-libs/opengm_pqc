package mlkem_test

import (
	"crypto/rand"
	"testing"

	"github.com/opengm-libs/opengm_pqc/goapi/mlkem"
)

func TestMlkem512(t *testing.T) {
	dk, _ := mlkem.Mlkem512KeyGen(rand.Reader)
	ek := dk.EncapKey()
	key, c := ek.Encap()
	key2, _ := dk.Decap(c)
	for i := 0; i < 32; i++ {
		if key[i] != key2[i] {
			t.Fail()
		}
	}
	_ = dk.Encode()
	_ = ek.Encode()

}

func BenchmarkMlkem512KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = mlkem.Mlkem512KeyGen(rand.Reader)
	}
}

func BenchmarkMlkem512Encap(b *testing.B) {
	dk, _ := mlkem.Mlkem512KeyGen(rand.Reader)
	ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_, _ = ek.Encap()
	}
}

func BenchmarkMlkem512Decap(b *testing.B) {
	dk, _ := mlkem.Mlkem512KeyGen(rand.Reader)
	ek := dk.EncapKey()

	_, c := ek.Encap()

	for i := 0; i < b.N; i++ {
		dk.Decap(c)

	}
}

func BenchmarkMlkem512DkEncode(b *testing.B) {
	dk, _ := mlkem.Mlkem512KeyGen(rand.Reader)
	// ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_ = dk.Encode()
	}
}

func BenchmarkMlkem512EkEncode(b *testing.B) {
	dk, _ := mlkem.Mlkem512KeyGen(rand.Reader)
	ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_ = ek.Encode()
	}
}
