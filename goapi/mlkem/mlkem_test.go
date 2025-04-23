package mlkem_test

import (
	"testing"

	"github.com/opengm-libs/opengm_pqc/goapi/mlkem"
)

func TestMlkem768(t *testing.T) {
	dk := mlkem.Mlkem768KeyGen()
	ek := dk.EncapKey()
	key, c := ek.Encap()
	key2 := dk.Decap(c)
	for i := 0; i < 32; i++ {
		if key[i] != key2[i] {
			t.Fail()
		}
	}
	_ = dk.Encode()
	_ = ek.Encode()

}

func BenchmarkMlkem768KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = mlkem.Mlkem768KeyGen()
	}
}

func BenchmarkMlkem768Encap(b *testing.B) {
	dk := mlkem.Mlkem768KeyGen()
	ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_, _ = ek.Encap()
	}
}

func BenchmarkMlkem768Decap(b *testing.B) {
	dk := mlkem.Mlkem768KeyGen()
	ek := dk.EncapKey()

	_, c := ek.Encap()

	for i := 0; i < b.N; i++ {
		_ = dk.Decap(c)

	}
}

func BenchmarkMlkem768DkEncode(b *testing.B) {
	dk := mlkem.Mlkem768KeyGen()
	// ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_ = dk.Encode()
	}
}

func BenchmarkMlkem768EkEncode(b *testing.B) {
	dk := mlkem.Mlkem768KeyGen()
	ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_ = ek.Encode()
	}
}
