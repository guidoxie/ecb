package ecb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

type ecb struct {
	b         cipher.Block
	blockSize int
}

// NewEncrypter 创建一个ECB模式的加密器
func NewEncrypter(key []byte) (*encrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &encrypter{block, block.BlockSize()}, nil
}

type encrypter ecb

func (x *encrypter) BlockSize() int { return x.blockSize }

func (x *encrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func (x *encrypter) Encrypt(src []byte) []byte {
	src = dup(src)
	paddedData := pkcs7Pad(src, x.blockSize)
	cipherData := make([]byte, len(paddedData))
	x.CryptBlocks(cipherData, paddedData)
	return cipherData
}

type decrypter ecb

// NewEncrypter 创建一个ECB模式的解密器
func NewDecrypter(key []byte) (*decrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &decrypter{block, block.BlockSize()}, nil
}

func (x *decrypter) BlockSize() int { return x.blockSize }

func (x *decrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func (x *decrypter) Decrypt(src []byte) []byte {
	dst := make([]byte, len(src))
	x.CryptBlocks(dst, src)
	trim := 0
	if len(dst) > 0 {
		trim = len(dst) - int(dst[len(dst)-1])
	}
	return dst[:trim]
}

// 填充模式
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func dup(p []byte) []byte {
	q := make([]byte, len(p))
	copy(q, p)
	return q
}
