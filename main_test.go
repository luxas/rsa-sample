package main

import (
	"bytes"
	"testing"
)

func TestEncrypt(t *testing.T) {
	tests := []struct {
		x, y []byte
		e, n uint64
	}{
		{
			x: []byte{4},
			e: 3,
			n: 33,
			y: []byte{31},
		},
		{
			x: []byte{0, 0, 0, 0, 0, 0, 0, 72},
			e: 512355097,
			n: 9434638355779701059,
			y: []byte{116, 202, 27, 157, 28, 28, 109, 89},
		},
	}
	for _, rt := range tests {
		var cipher bytes.Buffer
		w := NewRSAWriter(&cipher, rt.e, rt.n)
		w.Write(rt.x)
		actualy := cipher.Bytes()
		if !bytes.Equal(actualy, rt.y) {
			t.Errorf("actual y didn't match expected: %v != %v", actualy, rt.y)
		}
	}
}

func TestDecrypt(t *testing.T) {
	tests := []struct {
		x, y []byte
		d, n uint64
	}{
		{
			x: []byte{31},
			d: 7,
			n: 33,
			y: []byte{4},
		},
		{
			x: []byte{116, 202, 27, 157, 28, 28, 109, 89},
			d: 1127403723158652433,
			n: 9434638355779701059,
			y: []byte{72},
		},
	}
	for _, rt := range tests {
		cipher := bytes.NewBuffer(rt.x)
		actualy := make([]byte, len(rt.y))
		r := NewRSAReader(cipher, rt.d, rt.n)
		r.Read(actualy)
		if !bytes.Equal(actualy, rt.y) {
			t.Errorf("actual y didn't match expected: %x != %x", actualy, rt.y)
		}
	}
}
