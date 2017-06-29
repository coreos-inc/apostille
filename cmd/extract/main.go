package main

import (
	"fmt"

	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/utils"
	jose "github.com/dvsekhvalnov/jose2go"
)

func main() {
	publicKey := "\x305..."

	privateKey := "eyJALvUatRsxwPTzIvdwxD..."

	decryptedPrivKey, _, err := jose.Decode(privateKey, "abc...")
	if err != nil {
		fmt.Errorf("%v", err)
	}

	pubKey := data.NewPublicKey("ecdsa", []byte(publicKey))

	// Create a new PrivateKey with unencrypted bytes
	privKey, err := data.NewPrivateKey(pubKey, []byte(decryptedPrivKey))
	if err != nil {
		fmt.Errorf("%v", err)
	}

	encoded, err := utils.KeyToPEM(privKey, "root", "quay.io/*")
	if err != nil {
		fmt.Errorf("%v", err)
	}
	fmt.Println(string(encoded))
}
