package mlkem_test

import (
	"crypto/rand"
	"sync"
	"testing"

	"github.com/opengm-libs/opengm_pqc/goapi/mlkem"
)

func TestMlkem1024(t *testing.T) {
	dk, _ := mlkem.Mlkem1024KeyGen(rand.Reader)
	ek := dk.EncapKey()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for i := 0; i < 10000; i++ {
				key, c := ek.Encap()
				key2, _ := dk.Decap(c)
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
		_, _ = mlkem.Mlkem1024KeyGen(rand.Reader)
	}
}

func BenchmarkMlkem1024Encap(b *testing.B) {
	dk, _ := mlkem.Mlkem1024KeyGen(rand.Reader)
	ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_, _ = ek.Encap()
	}
}

func BenchmarkMlkem1024Decap(b *testing.B) {
	dk, _ := mlkem.Mlkem1024KeyGen(rand.Reader)
	ek := dk.EncapKey()

	_, c := ek.Encap()

	for i := 0; i < b.N; i++ {
		dk.Decap(c)

	}
}

func BenchmarkMlkem1024DkEncode(b *testing.B) {
	dk, _ := mlkem.Mlkem1024KeyGen(rand.Reader)
	// ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_ = dk.Encode()
	}
}

func BenchmarkMlkem1024EkEncode(b *testing.B) {
	dk, _ := mlkem.Mlkem1024KeyGen(rand.Reader)
	ek := dk.EncapKey()

	for i := 0; i < b.N; i++ {
		_ = ek.Encode()
	}
}
