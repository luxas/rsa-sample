package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 || (os.Args[1] != "gen" && len(os.Args) < 3) {
		return fmt.Errorf("Usage: rsa [gen|encrypt|decrypt] [filename]")
	}

	mode := os.Args[1]
	if mode == "gen" {
		return gen()
	}

	filename := os.Args[2]

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader
	var writer io.Writer
	if mode == "encrypt" {
		e, n, err := readKeyFile("public.key")
		if err != nil {
			return err
		}
		reader = file
		writer = NewRSAWriter(os.Stdout, e, n)
	} else if mode == "decrypt" {
		d, n, err := readKeyFile("private.key")
		if err != nil {
			return err
		}
		reader = NewRSAReader(file, d, n)
		writer = os.Stdout
	} else {
		return fmt.Errorf("mode must be gen, encrypt or decrypt")
	}

	// Read from the reader and stream the outputs through the writer
	if _, err = io.Copy(writer, reader); err != nil {
		return err
	}
	return nil
}

func gen() error {
	rand.Seed(time.Now().Unix())
	var p, q, e uint64
	var pbig, qbig, nbig big.Int
	for {
		p = uint64(rand.Uint32())
		q = uint64(rand.Uint32())
		pbig, qbig = bigUint64(p), bigUint64(q)
		if !pbig.ProbablyPrime(20) || !qbig.ProbablyPrime(20) {
			continue
		}

		nbig.Mul(&pbig, &qbig)
		if nbig.BitLen() == 64 {
			break
		}
	}

	var ebig, mbig, dbig, a, b, gcd big.Int

	mbig.Mul((&big.Int{}).Sub(&pbig, big.NewInt(1)), (&big.Int{}).Sub(&qbig, big.NewInt(1)))

	for {
		e = uint64(rand.Uint32())
		if !(3 <= e && e < mbig.Uint64()) {
			continue
		}
		ebig = bigUint64(e)
		gcd.GCD(&a, &b, &mbig, &ebig)
		if gcd.Uint64() != 1 {
			continue
		}
		if b.Int64() < 0 {
			dbig.Add(&b, &mbig)
		} else {
			dbig.Set(&b)
		}
		break
	}
	//fmt.Printf("p=%d, q=%d, n=%d, m=%d, e=%d, d=%d\n", p, q, nbig.Uint64(), mbig.Uint64(), e, dbig.Uint64())
	if err := ioutil.WriteFile("public.key", []byte(fmt.Sprintf("%d,%d", e, nbig.Uint64())), 0644); err != nil {
		return err
	}
	return ioutil.WriteFile("private.key", []byte(fmt.Sprintf("%d,%d", dbig.Uint64(), nbig.Uint64())), 0644)
}

// RSAWriter implements the io.Writer interface
var _ io.Writer = &RSAWriter{}

// NewRSAWriter creates a new RSA writer
func NewRSAWriter(w io.Writer, e, n uint64) *RSAWriter {
	nbig, ebig := bigUint64(n), bigUint64(e)
	bytes := uint64(nbig.BitLen() / 8)
	if bytes < 1 {
		bytes = 1
	}
	return &RSAWriter{
		w:     w,
		n:     &nbig,
		e:     &ebig,
		bytes: bytes,
	}
}

// RSAWriter wraps an io.Writer and encrypts using RSA
type RSAWriter struct {
	w     io.Writer
	n, e  *big.Int
	bytes uint64
}

func (w *RSAWriter) Write(p []byte) (n int, err error) {
	var buf []byte
	var upper int
	for {
		upper = n + int(w.bytes)
		if upper > len(p) {
			upper = len(p)
		}
		buf = p[n:upper]
		_, err = w.w.Write(w.encrypt(buf))
		n = upper
		if n == len(p) || err != nil {
			break
		}
	}
	if n == 0 && err == nil {
		err = io.EOF
	}
	return
}

func (w *RSAWriter) encrypt(x []byte) []byte {
	i := (&big.Int{}).SetBytes(x)
	return powmod(i, w.e, w.n).Bytes()
}

// RSAReader implements the io.Reader interface
var _ io.Reader = &RSAReader{}

// NewRSAReader creates a new RSA reader
func NewRSAReader(r io.Reader, d, n uint64) *RSAReader {
	nbig, dbig := bigUint64(n), bigUint64(d)
	bytes := uint64(nbig.BitLen() / 8)
	if bytes < 1 {
		bytes = 1
	}
	return &RSAReader{
		r:     r,
		n:     &nbig,
		d:     &dbig,
		bytes: bytes,
	}
}

// RSAReader wraps an io.Reader and decrypts using RSA
type RSAReader struct {
	r     io.Reader
	d, n  *big.Int
	bytes uint64
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
	i := (&big.Int{}).SetBytes(x)
	return powmod(i, r.d, r.n).Bytes()
}

func powmod(a, b, c *big.Int) *big.Int {
	return (&big.Int{}).Exp(a, b, c)
}

func bigUint64(val uint64) big.Int {
	return *(&big.Int{}).SetUint64(val)
}

func readKeyFile(filename string) (uint64, uint64, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return 0, 0, err
	}
	parts := strings.Split(string(content), ",")
	a, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	b, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return a, b, nil
}
