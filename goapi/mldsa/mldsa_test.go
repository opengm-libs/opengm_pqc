package mldsa

import (
	"crypto/rand"
	"testing"
)

func TestMldsa44(t *testing.T) {
	for i := 0; i < 1000; i++ {
		sk := Mldsa44KeyGen()
		pk := sk.PublicKey()
		m := make([]byte, 32)
		rand.Reader.Read(m)
		sig := sk.Sign(m, rand.Reader)

		ok := pk.Verify(sig, m)
		if !ok {
			t.Fatal()
		}
	}
}

func TestMldsa65(t *testing.T) {
	for i := 0; i < 1000; i++ {
		sk := Mldsa65KeyGen()
		pk := sk.PublicKey()
		m := make([]byte, 32)
		rand.Reader.Read(m)
		sig := sk.Sign(m, rand.Reader)

		ok := pk.Verify(sig, m)
		if !ok {
			t.Fatal()
		}
	}
}

func TestMldsa87(t *testing.T) {
	for i := 0; i < 1000; i++ {
		sk := Mldsa87KeyGen()
		pk := sk.PublicKey()
		m := make([]byte, 32)
		rand.Reader.Read(m)
		sig := sk.Sign(m, rand.Reader)

		ok := pk.Verify(sig, m)
		if !ok {
			t.Fatal()
		}
	}
}

func BenchmarkMldsaSign44(b *testing.B) {
	sk := Mldsa44KeyGen()
	m := make([]byte, 32)
	rand.Reader.Read(m)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sk.Sign(m, rand.Reader)
	}
}

func BenchmarkMldsaSign65(b *testing.B) {
	sk := Mldsa65KeyGen()
	m := make([]byte, 32)
	rand.Reader.Read(m)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sk.Sign(m, rand.Reader)
	}
}

func BenchmarkMldsaSign87(b *testing.B) {
	sk := Mldsa87KeyGen()
	m := make([]byte, 32)
	rand.Reader.Read(m)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sk.Sign(m, rand.Reader)
	}
}

func BenchmarkMldsaVerify44(b *testing.B) {
	sk := Mldsa44KeyGen()
	pk := sk.PublicKey()
	m := make([]byte, 32)
	rand.Reader.Read(m)
	sig := sk.Sign(m, rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, m)
	}

}

func BenchmarkMldsaVerify65(b *testing.B) {
	sk := Mldsa65KeyGen()
	pk := sk.PublicKey()
	m := make([]byte, 32)
	rand.Reader.Read(m)
	sig := sk.Sign(m, rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, m)
	}

}

func BenchmarkMldsaVerify87(b *testing.B) {
	sk := Mldsa87KeyGen()
	pk := sk.PublicKey()
	m := make([]byte, 32)
	rand.Reader.Read(m)
	sig := sk.Sign(m, rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, m)
	}

}
