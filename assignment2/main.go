package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"log"
)

type CryptoItem struct {
	mode                string
	key, iv, ciphertext []byte
}

func (ci *CryptoItem) UnmarshalJSON(jsonBytes []byte) error {
	var JSONItem struct {
		Mode, Key, Ciphertext string
	}

	err := json.Unmarshal(jsonBytes, &JSONItem)
	if err != nil {
		return err
	}

	ci.mode = JSONItem.Mode
	ci.key, err = hex.DecodeString(JSONItem.Key)
	if err != nil {
		return err
	}
	ci.iv, err = hex.DecodeString(JSONItem.Ciphertext[:32])
	if err != nil {
		return err
	}
	ci.ciphertext, err = hex.DecodeString(JSONItem.Ciphertext[32:])
	if err != nil {
		return err
	}
	return nil
}

var (
	TargetItems []CryptoItem
)

func main() {
	err := loadCipherTexts("ciphertexts.json")
	if err != nil {
		log.Fatal(err)
	}

	for _, item := range TargetItems {
		var result []byte

		ciph, err := aes.NewCipher(item.key)
		if err != nil {
			log.Fatal(err)
		}
		if item.mode == "CBC" {
			result, err = DecryptCBC(ciph, item.iv, item.ciphertext)
			if err != nil {
				log.Fatal(err)
			}
		}
		if item.mode == "CTR" {
			result, err = DecryptCTR(ciph, item.iv, item.ciphertext)
			if err != nil {
				log.Fatal(err)
			}
		}
		spew.Dump(item)
		fmt.Println("Decrypted: " + string(result) + "\n")
	}

}

func DecryptCBC(ciph cipher.Block, iv []byte, ciphertext []byte) ([]byte, error) {
	return nil, nil
}

func DecryptCTR(ciph cipher.Block, iv []byte, ciphertext []byte) ([]byte, error) {
	return nil, nil
}

func loadCipherTexts(filename string) error {
	contents, err := ioutil.ReadFile(filename) // For read access.
	if err != nil {
		return err
	}

	json.Unmarshal(contents, &TargetItems)

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func xor(a, b []byte) []byte {
	xoredlen := min(len(a), len(b))
	xored := make([]byte, xoredlen)
	for i := 0; i < xoredlen; i++ {
		xored[i] = a[i] ^ b[i]
	}
	return xored
}
