package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"log"
)

const (
	letters = " etaoinshrdlcumw]wfgypbvkjxqzTASHWIOBMFCLDPNEGRYUVJKQXZ" // Relative letter frequency for both upper and lowercase letters, in decending order.
	target  = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
)

// xorKey is just a way of keeping track of which ciphertexts correspond to which xoredtexted
type xorKey struct {
	a, b int
}

var (
	ciphertexts [][]byte
	xoredtexts  map[xorKey][]byte        // The key corresponds to
	keyguesse   []map[byte]float64       // We will list our guesses for the key here. keyguesse is the same size as the shortest ciphertext
	keylen      int                = 255 // The keylen is the number of key characters we will try to guesse. For simplicity, this is equal to the shortest ciphertext.
	likelykey   []byte                   // Our best guesse for the key
	frequencies = map[rune]float64{
		' ': 25.00,
		'e': 12.702,
		't': 9.056,
		'a': 8.167,
		'o': 7.507,
		'i': 6.966,
		'n': 6.749,
		's': 6.327,
		'h': 6.094,
		'r': 5.987,
		'd': 4.253,
		'l': 4.025,
		'c': 2.782,
		'u': 2.758,
		'm': 2.406,
		'w': 2.360,
		'f': 2.228,
		'g': 2.015,
		'y': 1.974,
		'p': 1.929,
		'b': 1.492,
		'v': 0.978,
		'k': 0.772,
		'x': 0.153,
		'q': 0.095,
		'z': 0.074,
	}
)

func main() {
	err := loadCipherTexts("ciphertexts.txt")
	if err != nil {
		log.Fatal(err)
	}

	// xor the ciphertexts together
	xoredtexts = make(map[xorKey][]byte)
	for i := 0; i < len(ciphertexts); i++ {
		for j := 0; j < len(ciphertexts); j++ {
			xoredtexts[xorKey{i, j}] = xor(ciphertexts[i], ciphertexts[j])
		}
	}

	// Initialize our keyguesse
	keyguesse = make([]map[byte]float64, keylen)
	for i, _ := range keyguesse {
		keyguesse[i] = make(map[byte]float64)
	}

	for common, weight := range frequencies {
		// Now we look at all instances of of the common letter and build a list of likely keys.
		checkchars := make([]byte, len(letters))
		for c, l := range letters {
			checkchars[c] = byte(common) ^ byte(l)
		}

		// Now we go through the xoredtext and look for instances of the checkchars, if we find one, we mark a corresponding guesse in the keyguesse
		for key, xoredtext := range xoredtexts {
			for i, xorchar := range xoredtext {
				if i > keylen-1 {
					break
				}
				for _, checkchar := range checkchars {
					if checkchar == xorchar {
						// We have a match. The XOR text contains a checkchar. Which means that it's likely that m1 or m2 have either common or a common^checkchar at this location.
						// We need to go back to one of the messages and XOR common and common^checkchar to recover the two key-guesses
						guesse1 := ciphertexts[key.a][i] ^ byte(common)
						guesse2 := ciphertexts[key.a][i] ^ byte(common) ^ checkchar
						keyguesse[i][guesse1] += weight
						keyguesse[i][guesse2] += weight
					}
				}
			}
		}
	}

	// Compute the most likely key
	for _, guesses := range keyguesse {
		var byteguesse byte
		var biggest float64 = 0

		for guesse, likelyhood := range guesses {
			if likelyhood > biggest {
				byteguesse = guesse
				biggest = likelyhood
			}
		}
		likelykey = append(likelykey, byteguesse)
	}

	// Now that we have a likely key, let's output the messages decrypted with that key
	fmt.Println("Most likely guessed key: ", likelykey)
	for i, text := range ciphertexts {
		fmt.Println("Decryption of ciphertext", i+1, ":")
		spew.Dump(xor(text, likelykey))
	}

	// Decrypt the target text
	decodedTarget, err := hex.DecodeString(target)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Decryption of target text:")
	fmt.Println(string(xor(decodedTarget, likelykey)))
}

func loadCipherTexts(filename string) error {
	contents, err := ioutil.ReadFile(filename) // For read access.
	if err != nil {
		return err
	}
	for _, hexedciphertext := range bytes.Split(contents, []byte("\n")) {
		ciphertext := make([]byte, hex.DecodedLen(len(hexedciphertext)))
		i, err := hex.Decode(ciphertext, hexedciphertext)
		if err != nil {
			return err
		}
		if i < keylen {
			keylen = i
		}
		ciphertexts = append(ciphertexts, ciphertext)
	}

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
