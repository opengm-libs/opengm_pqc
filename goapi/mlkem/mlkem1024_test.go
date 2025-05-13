package mlkem_test

import (
	"sync"
	"testing"

	"github.com/opengm-libs/opengm_pqc/goapi/mlkem"
)

func TestMlkem1024(t *testing.T) {
	dk := mlkem.Mlkem1024KeyGen()
	ek := dk.EncapKey()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for i := 0; i < 10000; i++ {
				key, c := ek.Encap()
				key2 := dk.Decap(c)
				for i := 0; i < 32; i++ {
					if key[i] != key2[i] {
						t.Fail()
					}
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func BenchmarkMlkem1024KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = mlkem.Mlkem1024KeyGen()
	}
}

func BenchmarkMlkem1024Encap(b *testing.B) {
	dk := mlkem.Mlkem1024KeyGen()
	ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_, _ = ek.Encap()
	}
}

func BenchmarkMlkem1024Decap(b *testing.B) {
	dk := mlkem.Mlkem1024KeyGen()
	ek := dk.EncapKey()

	_, c := ek.Encap()

	for i := 0; i < b.N; i++ {
		_ = dk.Decap(c)

	}
}

func BenchmarkMlkem1024DkEncode(b *testing.B) {
	dk := mlkem.Mlkem1024KeyGen()
	// ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_ = dk.Encode()
	}
}

func BenchmarkMlkem1024EkEncode(b *testing.B) {
	dk := mlkem.Mlkem1024KeyGen()
	ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_ = ek.Encode()
	}
}
