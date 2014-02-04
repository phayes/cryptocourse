package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/phayes/mobytes"
	"io/ioutil"
	"log"
	"math/big"
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
	var resultblocks [][]byte
	blocks := mobytes.SplitEvery(ciphertext, 16)
	for i, block := range blocks {
		decrypted := make([]byte, 16)
		ciph.Decrypt(decrypted, block)
		if i == 0 {
			decrypted = mobytes.XOR(decrypted, iv)
		} else {
			decrypted = mobytes.XOR(decrypted, blocks[i-1])
		}
		resultblocks = append(resultblocks, decrypted)
	}
	return bytes.Join(resultblocks, nil), nil
}

func DecryptCTR(ciph cipher.Block, iv []byte, ciphertext []byte) ([]byte, error) {
	var pad []byte
	var mixin big.Int
	mixin.SetBytes(iv)
	for i := 0; i <= len(ciphertext)/16; i++ {
		if i != 0 {
			mixin.Add(&mixin, big.NewInt(1)) // mixin++
		}
		encrypted := make([]byte, 16)
		ciph.Encrypt(encrypted, mixin.Bytes())
		pad = append(pad, encrypted...)
	}
	return mobytes.XOR(ciphertext, pad), nil
}

func loadCipherTexts(filename string) error {
	contents, err := ioutil.ReadFile(filename) // For read access.
	if err != nil {
		return err
	}

	json.Unmarshal(contents, &TargetItems)

	return nil
}
