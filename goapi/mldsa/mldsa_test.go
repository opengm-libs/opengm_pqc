package mldsa

import (
	"crypto/rand"
	"testing"
)

func TestMldsa44(t *testing.T) {
	for i := 0; i < 1000; i++ {
		sk, _ := Mldsa44KeyGen(rand.Reader)
		pk := sk.PublicKey()
		m := make([]byte, 32)
		rand.Reader.Read(m)
		sig, _ := sk.Sign(m, rand.Reader)

		ok := pk.Verify(sig, m)
		if !ok {
			t.Fatal()
		}
	}
}

func TestMldsa65(t *testing.T) {
	for i := 0; i < 1000; i++ {
		sk, _ := Mldsa65KeyGen(rand.Reader)
		pk := sk.PublicKey()
		m := make([]byte, 32)
		rand.Reader.Read(m)
		sig, _ := sk.Sign(m, rand.Reader)

		ok := pk.Verify(sig, m)
		if !ok {
			t.Fatal()
		}
	}
}

func TestMldsa87(t *testing.T) {
	for i := 0; i < 1000000; i++ {
		sk, _ := Mldsa87KeyGen(rand.Reader)
		pk := sk.PublicKey()
		m := make([]byte, 32)
		rand.Reader.Read(m)
		sig, _ := sk.Sign(m, rand.Reader)

		ok := pk.Verify(sig, m)
		if !ok {
			t.Fatal()
		}
	}
}

func BenchmarkMldsaSign44(b *testing.B) {
	sk, _ := Mldsa44KeyGen(rand.Reader)
	m := make([]byte, 32)
	rand.Reader.Read(m)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sk.Sign(m, rand.Reader)
	}
}

func BenchmarkMldsaSign65(b *testing.B) {
	sk, _ := Mldsa65KeyGen(rand.Reader)
	m := make([]byte, 32)
	rand.Reader.Read(m)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sk.Sign(m, rand.Reader)
	}
}

func BenchmarkMldsaSign87(b *testing.B) {
	sk, _ := Mldsa87KeyGen(rand.Reader)
	m := make([]byte, 32)
	rand.Reader.Read(m)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sk.Sign(m, rand.Reader)
	}
}

func BenchmarkMldsaVerify44(b *testing.B) {
	sk, _ := Mldsa44KeyGen(rand.Reader)
	pk := sk.PublicKey()
	m := make([]byte, 32)
	rand.Reader.Read(m)
	sig, _ := sk.Sign(m, rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, m)
	}

}

func BenchmarkMldsaVerify65(b *testing.B) {
	sk, _ := Mldsa65KeyGen(rand.Reader)
	pk := sk.PublicKey()
	m := make([]byte, 32)
	rand.Reader.Read(m)
	sig, _ := sk.Sign(m, rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, m)
	}

}

func BenchmarkMldsaVerify87(b *testing.B) {
	sk, _ := Mldsa87KeyGen(rand.Reader)
	pk := sk.PublicKey()
	m := make([]byte, 32)
	rand.Reader.Read(m)
	sig, _ := sk.Sign(m, rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, m)
	}

}
