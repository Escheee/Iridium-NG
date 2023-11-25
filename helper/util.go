package helper

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func removeMagic(data []byte) []byte {
	cut := data[5]
	data = data[8+2:]            // Removes token + two byte magic
	data = data[0 : len(data)-2] // Removes two byte magic at the end
	data = data[cut:]
	return data
}

func removeHeaderForParse(data []byte) []byte {
	cut := data[6]
	data = removeMagic(data)
	return data[cut:]
}

func xorDecrypt(data []byte, key []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key[i%len(key)]
	}
}

func reformData(data []byte) []byte {
	i := 0
	tokenSizeTotal := 0
	var messages [][]byte
	for i < len(data) {
		convId := data[i : i+4]
		remainingHeader := data[i+8 : i+28]
		contentLen := int(binary.LittleEndian.Uint32(data[i+24 : i+28]))
		content := data[i+28 : (i + 28 + contentLen)]

		formattedMessage := make([]byte, 24+contentLen)
		copy(formattedMessage, convId)
		copy(formattedMessage[4:], remainingHeader)
		copy(formattedMessage[24:], content)
		i += 28 + contentLen
		tokenSizeTotal += 4
		messages = append(messages, formattedMessage)
	}

	return bytes.Join(messages, []byte{})
}

func bruteforce(ms, seed uint64, p []byte) (uint64, []byte) {
	r1 := NewCSRand()
	r2 := NewMTRand()
	v := binary.BigEndian.Uint64(p)
	for i := uint64(0); i < 3000; i++ {
		r1.Seed(int64(ms + i))
		for j := uint64(0); j < 1000; j++ {
			s := r1.Uint64()
			r2.Seed(int64(s ^ seed))
			r2.Seed(int64(r2.Uint64()))
			r2.Uint64()
			if (v^r2.Uint64())&0xFFFF0000FF00FFFF == 0x4567000000000000 {
				// log.Info().Uint64("#seed", ms+i).Uint64("depth", j).Msg("Found seed")
				return ms + i, NewKeyBlock(s ^ seed).Key()
			}
			if i != 0 && (i > 100 || i+j > 100) {
				break
			}
		}
		r1.Seed(int64(ms - i - 1))
		for j := uint64(0); j < 1000; j++ {
			s := r1.Uint64()
			r2.Seed(int64(s ^ seed))
			r2.Seed(int64(r2.Uint64()))
			r2.Uint64()
			if (v^r2.Uint64())&0xFFFF0000FF00FFFF == 0x4567000000000000 {
				// log.Info().Uint64("#seed", ms-i-1).Uint64("depth", j).Msg("Found seed")
				return ms - i - 1, NewKeyBlock(s ^ seed).Key()
			}
			if i+1 > 100 || i+j+1 > 100 {
				break
			}
		}
	}
	return 0, nil
}

func decrypt(keypath string, ciphertext []byte) ([]byte, error) {
	rest, _ := os.ReadFile(keypath)
	var ok bool
	var block *pem.Block
	var priv *rsa.PrivateKey
	for {
		block, rest = pem.Decode(rest)
		if block.Type == "RSA PRIVATE KEY" {
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Println(err)
			} else if priv, ok = k.(*rsa.PrivateKey); !ok {
				log.Println(fmt.Errorf("failed to parse private key"))
			}
			break
		}
		if len(rest) == 0 {
			if priv == nil {
				log.Println(fmt.Errorf("failed to parse private key"))
			}
			break
		}
	}
	out := make([]byte, 0, 1024)
	for len(ciphertext) > 0 {
		chunkSize := 256
		if chunkSize > len(ciphertext) {
			chunkSize = len(ciphertext)
		}
		chunk := ciphertext[:chunkSize]
		ciphertext = ciphertext[chunkSize:]
		b, err := rsa.DecryptPKCS1v15(rand.Reader, priv, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}
