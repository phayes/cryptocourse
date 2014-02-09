package main

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/davecgh/go-spew/spew"
	"io"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Invalid number of arguments")
	}
	file, err := os.Open(os.Args[1])

	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	fileinfo, err := file.Stat()
	if err != nil {
		log.Fatal(err)
	}
	filesize := fileinfo.Size()

	numchunks := filesize / 1024

	var prevchunk []byte
	for i := 0; int64(i) <= numchunks; i++ {
		chunknum := numchunks - int64(i)
		offset := chunknum * 1024
		curchunk := make([]byte, 1024, 1024)
		n, err := file.ReadAt(curchunk, offset)
		if err != nil {
			if err != io.EOF {
				log.Fatal(err)
			}
		}
		curchunk = curchunk[:n] //Make sure we are only dealing with the bytes actually read

		if prevchunk != nil {
			hash := sha256.Sum256(prevchunk)
			curchunk = append(curchunk, hash[:32]...)
		}
		prevchunk = curchunk
	}
	hash := sha256.Sum256(prevchunk)
	spew.Dump(hex.EncodeToString(hash[:32]))
}
