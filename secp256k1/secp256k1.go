package main

/*
#cgo CFLAGS: -I./libsecp256k1
#cgo CFLAGS: -I./libsecp256k1/include
#cgo CFLAGS: -I./libsecp256k1/src/

//#define HAVE_CONFIG_H 1
#include <stdbool.h>

#ifdef __SIZEOF_INT128__
#  define HAVE___INT128
#  define USE_FIELD_5X52
#  define USE_SCALAR_4X64
#else
#  define USE_FIELD_10X26
#  define USE_SCALAR_8X32
#endif
#define USE_ENDOMORPHISM
#define USE_NUM_NONE
#define USE_FIELD_INV_BUILTIN
#define USE_SCALAR_INV_BUILTIN
#define NDEBUG

#include "./libsecp256k1/src/secp256k1.c"

static secp256k1_context_t *gctx = NULL;
static void init_context() {
    gctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_COMMIT | SECP256K1_CONTEXT_RANGEPROOF);
}

static int extended_nonce_function( unsigned char *nonce32, const unsigned char *msg32,
									const unsigned char *key32, unsigned int attempt,
									const void *data ) {
	unsigned int* extra = (unsigned int*) data;
	(*extra)++;
	return secp256k1_nonce_function_default( nonce32, msg32, key32, *extra, 0 );
}

static int is_canonical( const unsigned char* data ) {
	return !(data[1] & 0x80)
			&& !(data[1] == 0 && !(data[2] & 0x80))
			&& !(data[33] & 0x80)
			&& !(data[33] == 0 && !(data[34] & 0x80));
}

static int sign_compact( const unsigned char* digest, const unsigned char *seckey, size_t seckey_size, bool require_canonical, unsigned char* compact_signature, size_t compact_signature_len) {
	int ret = 0;
	int recid;
	unsigned int counter = 0;
	do
	{
		ret = secp256k1_ecdsa_sign_compact( gctx, digest, compact_signature + 1, seckey, extended_nonce_function, &counter, &recid );
		if (ret == 0)
		{
			return 0;
		}
	} while( require_canonical && !is_canonical( compact_signature ) );
	compact_signature[0] = 27 + 4 + recid;
	return 1;
}

static int secp256k1_recover( const unsigned char* signature, size_t signature_size, const unsigned char* digest, size_t digest_size, unsigned char* pub_key, size_t pub_key_size, bool check_canonical )
{
	int nV = signature[0];
	if (nV<27 || nV>=35) {
		//"unable to reconstruct public key from signature" );
		return 0;
	}

	if( check_canonical ) {
		if (!is_canonical( signature )) {
			//"signature is not canonical"
			return 0;
		}
	}

	unsigned int pk_len;
	int ret = secp256k1_ecdsa_recover_compact( gctx, digest, signature + 1, pub_key, (int*) &pk_len, 1, (signature[0] - 27) & 3 );
	if (ret == 0) {
		return 0;
	}
	return pk_len == pub_key_size;
}

static int secp256k1_get_public_key(const unsigned char* seckey, size_t seckey_size, unsigned char* pubkey, size_t pubkey_size)
{
	unsigned int pk_len;
	int ret = secp256k1_ec_pubkey_create( gctx, pubkey, (int*) &pk_len, seckey, 1 );
	if (ret == 0) {
		return 0;
	}

	if (pk_len != pubkey_size) {
		return 0;
	}
	return 1;
}

*/
import "C"

import (
	"encoding/hex"
	"errors"
	"log"
	"time"
	"unsafe"
)

func SayHello() {
	println("Hello!")
}

func Init() {
	C.init_context()
}

func Sign(digest []byte, seckey []byte) ([]byte, error) {
	signature := make([]byte, 65)
	_digest := (*C.uchar)(unsafe.Pointer(&digest[0]))
	_seckey := (*C.uchar)(unsafe.Pointer(&seckey[0]))
	_signature := (*C.uchar)(unsafe.Pointer(&signature[0]))
	ret := C.sign_compact(_digest, _seckey, 32, (C.bool)(true), _signature, 65)
	if ret == 0 {
		return nil, errors.New("sign failed")
	}
	return signature, nil
}

//digest is 32 bytes
//signature is 65 bytes
//pubkey is 33 bytes
func Recover(digest []byte, signature []byte) ([]byte, error) {
	_digest := (*C.uchar)(unsafe.Pointer(&digest[0]))
	_signature := (*C.uchar)(unsafe.Pointer(&signature[0]))

	var pubkey_recovered [33]byte
	_pubkey_recovered := (*C.uchar)(unsafe.Pointer(&pubkey_recovered[0]))
	ret := C.secp256k1_recover(_signature, 65, _digest, 32, _pubkey_recovered, 33, (C.bool)(true))
	if ret == 0 {
		return nil, errors.New("recover failed")
	}
	return pubkey_recovered[:], nil
}

func GetPublicKey(seckey []byte) ([]byte, error) {
	if len(seckey) != 32 {
		return nil, errors.New("seckey must be 32 bytes")
	}

	_seckey := (*C.uchar)(unsafe.Pointer(&seckey[0]))
	var pubkey [33]byte
	_pubkey := (*C.uchar)(unsafe.Pointer(&pubkey[0]))
	ret := C.secp256k1_get_public_key(_seckey, 32, _pubkey, 33)
	if ret == 0 {
		return nil, errors.New("get public key failed")
	}
	return pubkey[:], nil
}

func main() {
	//	C.test_ge()
	Init()

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

	signature, err := Sign(digest, seckey)
	if err != nil {
		panic(err)
	}
	log.Println("++++++signature:", hex.EncodeToString(signature))

	pubKey, err := Recover(digest, signature)
	log.Println("++++++recovered pub key:", hex.EncodeToString(pubKey))

	pubkey, err := GetPublicKey(seckey)
	log.Println("++++++pub key:", hex.EncodeToString(pubkey))
	duration := time.Since(start)
	log.Println("++++++time:", duration)
}
