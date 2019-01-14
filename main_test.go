package main

import (
	"bytes"
	"testing"
)

func TestEuklides(t *testing.T) {
	tests := []struct {
		tal, faktor, a, b int64
	}{
		{
			tal:    40,
			faktor: 7,
			a:      3,
			b:      -17,
		},
	}
	for _, rt := range tests {
		actuala, actualb := euklides(rt.tal, rt.faktor)
		if actuala != rt.a {
			t.Errorf("actual a didn't match expected: %d != %d", actuala, rt.a)
		}
		if actualb != rt.b {
			t.Errorf("actual b didn't match expected: %d != %d", actualb, rt.b)
		}
	}
}

func TestEncrypt(t *testing.T) {
	tests := []struct {
		x       byte
		e, n, y int64
	}{
		{
			x: 8,
			e: 7,
			n: 55,
			y: 2,
		},
		{
			x: 115,
			e: 7,
			n: 55,
			y: 25,
		},
		{
			x: 72,
			e: 7,
			n: 55,
			y: 8,
		},
		{
			x: 72,
			e: 11,
			n: 217,
			y: 81,
		},
	}
	for _, rt := range tests {
		var buf bytes.Buffer
		w := NewRSAWriter(&buf, rt.n, rt.e)
		actualy := w.encrypt([]byte{rt.x})
		if int64(actualy[0]) != rt.y {
			t.Errorf("actual y didn't match expected: %d != %d", actualy, rt.y)
		}
	}
}

func TestDecrypt(t *testing.T) {
	tests := []struct {
		x          byte
		e, p, q, y int64
	}{
		{
			x: 2,
			e: 7,
			p: 5,
			q: 11,
			y: 8,
		},
		{
			x: 8,
			e: 7,
			p: 5,
			q: 11,
			y: 17,
		},
		{
			x: 81,
			e: 11,
			p: 7,
			q: 31,
			y: 72,
		},
	}
	for _, rt := range tests {
		var buf bytes.Buffer
		r := NewRSAReader(&buf, rt.e, rt.p, rt.q)
		actualy := r.decrypt([]byte{rt.x})
		if int64(actualy[0]) != rt.y {
			t.Errorf("actual y didn't match expected: %d != %d", actualy, rt.y)
		}
	}
}
