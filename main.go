package main

import (
	"encoding/hex"
	"log"
	"time"

	"github.com/learnforpractice/go-secp256k1/secp256k1"
)

func main() {
	secp256k1.SayHello()
	secp256k1.Init()

	// digest := make([]byte, 32)
	//	seckey := make([]byte, 32)
	digest, err := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	if err != nil {
		panic(err)
	}

	seckey, err := hex.DecodeString("99870ba61ad4bfae18a1c4cea5a6b48882b95633421b108497a2b53dc779a639")
	if err != nil {
		panic(err)
	}

	start := time.Now()

	signature, err := secp256k1.Sign(digest, seckey)
	if err != nil {
		panic(err)
	}
	log.Println("++++++signature:", hex.EncodeToString(signature))

	pubKey, err := secp256k1.Recover(digest, signature)
	log.Println("++++++recovered pub key:", hex.EncodeToString(pubKey))

	pubkey, err := secp256k1.GetPublicKey(seckey)
	log.Println("++++++pub key:", hex.EncodeToString(pubkey))
	duration := time.Since(start)
	log.Println("++++++duration:", duration)
}
