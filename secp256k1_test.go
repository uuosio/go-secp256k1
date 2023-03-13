package secp256k1

import (
	"encoding/hex"
	"log"
	"testing"
	"time"
)

func TestA(t *testing.T) {
	SayHello()
	Init()
	defer Destroy()

	// digest := make([]byte, 32)
	//	seckey := make([]byte, 32)
	digest, err := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	if err != nil {
		panic(err)
	}

	seckey, err := NewPrivateKeyFromHex("99870ba61ad4bfae18a1c4cea5a6b48882b95633421b108497a2b53dc779a639")
	if err != nil {
		panic(err)
	}

	start := time.Now()

	signature, err := Sign(digest, seckey)
	if err != nil {
		panic(err)
	}
	log.Println("++++++signature:", signature.String())

	{
		pubKey, _ := Recover(digest, signature)
		log.Println("++++++pubKeyBase58:", pubKey.String())
	}

	{
		pubkey, _ := GetPublicKey(seckey)
		log.Println("++++++pub key:", pubkey.String())
		duration := time.Since(start)
		log.Println("++++++duration:", duration)
	}

	priv, err := NewPrivateKeyFromBase58("5JRYimgLBrRLCBAcjHUWCYRv3asNedTYYzVgmiU4q2ZVxMBiJXL")
	if err != nil {
		panic(err)
	}
	log.Println("++++++priv key:", hex.EncodeToString(priv.Data[:]))

	priv, err = NewPrivateKeyFromBase58("PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V")
	if err != nil {
		panic(err)
	}
	log.Println("++++++priv key:", hex.EncodeToString(priv.Data[:]))

	pub := priv.GetPublicKey()
	log.Println("++++++pub key:", pub.String())
}

func TestB(t *testing.T) {
	Init()
	strPubEos := "EOS6t63xDyTbP8ncvZ9gjhkcrJbD1eueCfaNDAH4LV95XkpZasW9m"
	strPub := "PUB_K1_6t63xDyTbP8ncvZ9gjhkcrJbD1eueCfaNDAH4LV95XkpbfUBbq"
	pub, err := NewPublicKeyFromBase58(strPub)
	if err != nil {
		panic(err)
	}

	if strPubEos != pub.StringEOS() {
		panic("error")
	}

	if strPub != pub.String() {
		panic("error")
	}
}
