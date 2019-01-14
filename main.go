package main

import (
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
)

var (
	// Always needed
	e    = flag.Int64("e", 0, "A number that satisfies 1 < e < m and sgd(e,m) = 1")
	mode = flag.String("mode", "", "Either encrypt or decrypt")
	// Required when decrypting
	p = flag.Int64("p", 0, "One prime")
	q = flag.Int64("q", 0, "An other prime")
	// Required when encrypting
	n = flag.Int64("n", 0, "The public key, p * q")
)

func main() {
	if err := run(); err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flag.Parse()
	var err error
	var reader io.Reader
	var writer io.Writer
	if *mode == "encrypt" {
		if *e <= 0 || *n <= 0 {
			return fmt.Errorf("arguments n, and e are required")
		}
		file, err := os.Open("file.txt")
		if err != nil {
			return err
		}
		defer file.Close()
		reader = file
		writer = NewRSAWriter(os.Stdout, *n, *e)
	} else if *mode == "decrypt" {
		if *e <= 0 || *p <= 0 || *q <= 0 {
			return fmt.Errorf("arguments e, x, p and q are required")
		}
		file, err := os.Open("out.txt")
		if err != nil {
			return err
		}
		defer file.Close()
		reader = NewRSAReader(file, *e, *p, *q)
		writer = os.Stdout
	} else {
		return fmt.Errorf("mode must be either encrypt or decrypt")
	}
	if err != nil {
		return err
	}

	// Read from the reader and stream the outputs through the writer
	_, err = io.Copy(writer, reader)
	if err != nil {
		return err
	}
	return nil
}

// RSAWriter implements the io.Writer interface
var _ io.Writer = &RSAWriter{}

// NewRSAWriter creates a new RSA writer
func NewRSAWriter(w io.Writer, n, e int64) *RSAWriter {
	nbig := big.NewInt(n)
	return &RSAWriter{
		w:     w,
		n:     nbig,
		e:     big.NewInt(e),
		bytes: uint64(nbig.BitLen() / 8),
	}
}

// RSAWriter wraps an io.Writer and encrypts using RSA
type RSAWriter struct {
	w     io.Writer
	n, e  *big.Int
	bytes uint64
}

func (w *RSAWriter) Write(p []byte) (n int, err error) {
	var stop bool
	for {
		plain := make([]byte, w.bytes)
		for j := 0; j < int(w.bytes); j++ {
			plain = append(plain, p[n])
			n++
			if n == len(p) {
				stop = true
				break
			}
		}
		encrypted := w.encrypt(plain)
		_, err = w.w.Write(encrypted)
		if stop {
			break
		}
	}
	if n == 0 && err == nil {
		err = io.EOF
	}
	return
}

func (w *RSAWriter) encrypt(x []byte) []byte {
	i := &big.Int{}
	i.SetBytes(x)
	return powmod(i, w.e, w.n).Bytes()
}

// RSAReader implements the io.Reader interface
var _ io.Reader = &RSAReader{}

// NewRSAReader creates a new RSA reader
func NewRSAReader(r io.Reader, e, p, q int64) *RSAReader {
	n := p * q
	m := (p - 1) * (q - 1)
	_, d := euklides(m, e)

	if d < 0 {
		d += m
	}

	nbig := big.NewInt(n)

	return &RSAReader{
		r:     r,
		e:     big.NewInt(e),
		p:     big.NewInt(p),
		q:     big.NewInt(q),
		n:     nbig,
		m:     big.NewInt(m),
		d:     big.NewInt(d),
		bytes: uint64(nbig.BitLen() / 8),
	}
}

// RSAReader wraps an io.Reader and decrypts using RSA
type RSAReader struct {
	r                io.Reader
	e, p, q, n, m, d *big.Int
	bytes            uint64
}

func (r *RSAReader) Read(p []byte) (n int, err error) {
	encryptedbuf := make([]byte, r.bytes)
	n, err = r.r.Read(encryptedbuf)
	if err != nil && err != io.EOF {
		return
	}
	plain := r.decrypt(encryptedbuf)
	for i := 0; i < len(plain); i++ {
		p[i] = plain[i]
	}
	if err == io.EOF {
		return
	}
	return
}

func (r *RSAReader) decrypt(x []byte) []byte {
	i := &big.Int{}
	i.SetBytes(x)
	return powmod(i, r.d, r.n).Bytes()
}

func powmod(a, b, c *big.Int) *big.Int {
	return (&big.Int{}).Exp(a, b, c)
}

type euk struct {
	// r = 1 * x - b (stored here) * y
	store []int64
}

func euklides(tal, faktor int64) (int64, int64) {
	e := euk{}
	e.eukfn(tal, faktor)
	a, b := int64(0), int64(0)
	for i := len(e.store) - 1; i >= 0; i-- {
		num := e.store[i]
		if a == 0 && b == 0 {
			a = 1
			b = -num
		} else {
			newa := b
			b = a + b*-num
			a = newa
		}
	}
	return a, b
}

func (e *euk) eukfn(tal, faktor int64) {
	rest := int64(math.Mod(float64(tal), float64(faktor)))
	num := int64(tal / faktor)
	e.store = append(e.store, num)
	if rest == 1 {
		return
	}
	e.eukfn(faktor, rest)
}
