package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"

	"github.com/blackalex1/sentinel-core/pkg/crypto"
)

//export SentinelGenerateX25519Keys
func SentinelGenerateX25519Keys() *C.char {
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	respBytes, _ := json.Marshal(kp)
	return C.CString(string(respBytes))
}

//export SentinelGenerateVlessEncKeys
func SentinelGenerateVlessEncKeys() *C.char {
	keys, err := crypto.GenerateVlessEncKeys()
	if err != nil {
		errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
		return C.CString(string(errResp))
	}
	res := map[string]any{
		"success":  true,
		"x25519":   keys.X25519,
		"mlkem768": keys.MLKEM768,
	}
	bytes, _ := json.Marshal(res)
	return C.CString(string(bytes))
}

//export SentinelEncrypt
func SentinelEncrypt(data *C.char, secret *C.char) *C.char {
	plain := safeGoString(data)
	sec := safeGoString(secret)
	v, err := crypto.NewVault(sec)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	payload, err := v.EncryptString(plain)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	res, _ := json.Marshal(map[string]string{"payload": payload})
	return C.CString(string(res))
}

//export SentinelDecrypt
func SentinelDecrypt(payload *C.char, secret *C.char) *C.char {
	cipherPayload := safeGoString(payload)
	sec := safeGoString(secret)
	v, err := crypto.NewVault(sec)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	plain, err := v.DecryptString(cipherPayload)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	res, _ := json.Marshal(map[string]string{"plaintext": plain})
	return C.CString(string(res))
}

//export SentinelEncryptPayload
func SentinelEncryptPayload(plaintext *C.char, secret *C.char) *C.char {
	goPlaintext := safeGoString(plaintext)
	goSecret := safeGoString(secret)

	vault, err := crypto.NewVault(goSecret)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	enc, err := vault.EncryptString(goPlaintext)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	return C.CString(enc)
}

//export SentinelDecryptPayload
func SentinelDecryptPayload(ciphertext *C.char, secret *C.char) *C.char {
	goCipher := safeGoString(ciphertext)
	goSecret := safeGoString(secret)

	vault, err := crypto.NewVault(goSecret)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	dec, err := vault.DecryptString(goCipher)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	return C.CString(dec)
}
