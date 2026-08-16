package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/blackalex1/sentinel-core/pkg/crypto"
)

func handleEncrypt() {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	secret := fs.String("secret", "", "Master secret key")
	text := fs.String("text", "", "Plaintext to encrypt")
	data := fs.String("data", "", "Data alias")
	_ = fs.Parse(os.Args[2:])

	val := *text
	if val == "" {
		val = *data
	}

	if *secret == "" || val == "" {
		fmt.Println("Error: --secret and --text/--data are required")
		exitFunc(1)
		return
	}

	vault, err := crypto.NewVault(*secret)
	if err != nil {
		fmt.Printf("Vault error: %v\n", err)
		exitFunc(1)
		return
	}

	enc, err := vault.EncryptString(val)
	if err != nil {
		fmt.Printf("Encrypt error: %v\n", err)
		exitFunc(1)
		return
	}

	res, _ := json.Marshal(map[string]string{"payload": enc})
	fmt.Println(string(res))
}

func handleDecrypt() {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	secret := fs.String("secret", "", "Master secret key")
	payload := fs.String("payload", "", "Ciphertext to decrypt")
	_ = fs.Parse(os.Args[2:])

	if *secret == "" || *payload == "" {
		fmt.Println("Error: --secret and --payload are required")
		exitFunc(1)
		return
	}

	vault, err := crypto.NewVault(*secret)
	if err != nil {
		fmt.Printf("Vault error: %v\n", err)
		exitFunc(1)
		return
	}

	dec, err := vault.DecryptString(*payload)
	if err != nil {
		fmt.Printf("Decrypt error: %v\n", err)
		exitFunc(1)
		return
	}

	res, _ := json.Marshal(map[string]string{"plaintext": dec})
	fmt.Println(string(res))
}

func handleKeypair() {
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		fmt.Printf("Key error: %v\n", err)
		exitFunc(1)
		return
	}
	bytes, _ := json.MarshalIndent(kp, "", "  ")
	fmt.Println(string(bytes))
}

func handleVlessEnc() {
	keys, err := crypto.GenerateVlessEncKeys()
	if err != nil {
		fmt.Printf("Key generation error: %v\n", err)
		exitFunc(1)
		return
	}
	res := map[string]any{
		"success":  true,
		"x25519":   keys.X25519,
		"mlkem768": keys.MLKEM768,
	}
	data, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(data))
}
