package coursework_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"testing"

	"coursework/crypto/magenta"
	"coursework/crypto/rc6"
)

type knownAnswer struct {
	key        string
	plaintext  string
	ciphertext string
}

const (
	zeroBlock = "00000000000000000000000000000000"
	rc6Input  = "02132435465768798a9bacbdcedfe0f1"
	rc6Key    = "0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe"
	magInput  = "000102030405060708090a0b0c0d0e0f"
	magKey    = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"
)

var cipherSuites = []struct {
	name      string
	newCipher func([]byte) (cipher.Block, error)
	vectors   []knownAnswer
}{
	{
		name:      "RC6",
		newCipher: rc6.NewCipher,
		// The RC6 Block Cipher, v1.1 (1998), Appendix, p. 20.
		vectors: []knownAnswer{
			{zeroBlock, zeroBlock, "8fc3a53656b1f778c129df4e9848a41e"},
			{rc6Key[:32], rc6Input, "524e192f4715c6231f51f6367ea43f18"},
			{zeroBlock + zeroBlock[:16], zeroBlock, "6cd61bcb190b30384e8a3f168690ae82"},
			{rc6Key[:48], rc6Input, "688329d019e505041e52e92af95291d4"},
			{zeroBlock + zeroBlock, zeroBlock, "8f5fbd0510d15fa893fa3fda6e857ec2"},
			{rc6Key, rc6Input, "c8241816f0d7e48920ad16a1674e5d48"},
		},
	},
	{
		name:      "MAGENTA",
		newCipher: magenta.NewCipher,
		// Round 1 AES submission: ecb_int.txt, ecb_tbl.txt, ecb_vk.txt, and ecb_vt.txt.
		// https://web.archive.org/web/20070109105056id_/http://csrc.nist.gov/CryptoToolkit/aes/round1/testvals/magenta-vals.zip
		vectors: []knownAnswer{
			{magKey[:32], magInput, "0909105491f0ef3d363eae828a504e2b"},
			{zeroBlock, zeroBlock, "ca7d2b729ff35fbd75e8c72e8049f7d4"},
			{zeroBlock, "80000000000000000000000000000000", "f6b50c496e9a97abe925da2e7c891974"},
			{"80000000000000000000000000000000", zeroBlock, "d923ff2b95212ca5581693f71137aafa"},
			{"40000000000000000000000000000000", zeroBlock, "462e3204fcee82beae4fa8cb66696502"},
			{magKey[:48], magInput, "b553e21c2169caea8f67d2936ea3b086"},
			{zeroBlock + zeroBlock[:16], zeroBlock, "ca7d2b729ff35fbd75e8c72e8049f7d4"},
			{"800000000000000000000000000000000000000000000000", zeroBlock, "588ebee01ddf366998f50d3ff58beaec"},
			{magKey, magInput, "bc1128eaca812a9e6564107758a28857"},
			{zeroBlock + zeroBlock, zeroBlock, "f0f66c085c77ca9433c95e0300c71891"},
			{"8000000000000000000000000000000000000000000000000000000000000000", zeroBlock, "9a199e39c2df1f1c17cea243f8e5147e"},
		},
	},
}

func TestKnownAnswers(t *testing.T) {
	for _, suite := range cipherSuites {
		t.Run(suite.name, func(t *testing.T) {
			for i, vector := range suite.vectors {
				t.Run(fmt.Sprintf("key%d_vector%d", len(vector.key)*4, i+1), func(t *testing.T) {
					key := decodeHex(t, vector.key)
					plaintext := decodeHex(t, vector.plaintext)
					ciphertext := decodeHex(t, vector.ciphertext)
					block, err := suite.newCipher(key)
					if err != nil {
						t.Fatal(err)
					}
					if got := block.BlockSize(); got != 16 {
						t.Fatalf("BlockSize() = %d, want 16", got)
					}
					for i := range key {
						key[i] ^= 0xff
					}

					// A larger destination must retain the bytes after the first block.
					got := make([]byte, block.BlockSize()+1)
					got[block.BlockSize()] = 0xa5
					block.Encrypt(got, plaintext)
					if want := append(bytes.Clone(ciphertext), 0xa5); !bytes.Equal(got, want) {
						t.Errorf("Encrypt() = %x, want %x", got, want)
					}

					copy(got, ciphertext)
					block.Decrypt(got, got)
					if want := append(bytes.Clone(plaintext), 0xa5); !bytes.Equal(got, want) {
						t.Fatalf("Decrypt() in place = %x, want %x", got, want)
					}
					block.Encrypt(got, got)
					if want := append(bytes.Clone(ciphertext), 0xa5); !bytes.Equal(got, want) {
						t.Errorf("Encrypt() in place = %x, want %x", got, want)
					}
				})
			}
		})
	}
}

func TestInvalidKeySizes(t *testing.T) {
	for _, suite := range cipherSuites {
		t.Run(suite.name, func(t *testing.T) {
			for _, size := range []int{0, 15, 17, 23, 25, 31, 33} {
				block, err := suite.newCipher(make([]byte, size))
				if block != nil || err == nil {
					t.Errorf("NewCipher accepted a %d-byte key", size)
				}
			}
		})
	}
}

func TestCTRCompatibility(t *testing.T) {
	for _, suite := range cipherSuites {
		t.Run(suite.name, func(t *testing.T) {
			block, err := suite.newCipher(make([]byte, 16))
			if err != nil {
				t.Fatal(err)
			}
			iv := decodeHex(t, "0f0e0d0c0b0a09080706050403020100")
			plaintext := []byte("Binary data across block boundaries.\x00\xff")
			got := bytes.Clone(plaintext)
			cipher.NewCTR(block, iv).XORKeyStream(got, got)
			if bytes.Equal(got, plaintext) {
				t.Fatal("CTR left the plaintext unchanged")
			}
			cipher.NewCTR(block, iv).XORKeyStream(got, got)
			if !bytes.Equal(got, plaintext) {
				t.Errorf("CTR round trip = %x, want %x", got, plaintext)
			}
		})
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid test vector %q: %v", value, err)
	}
	return data
}
