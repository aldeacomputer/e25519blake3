package ed25519blake3

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/aldeacomputer/ed25519blake3/aldeacrypto"
)

func main() {
	seed, _ := hex.DecodeString("164b0ec3d0355a76ac404228525f7ab9e45ebad8a3ecb5f71167df79c902587a")

	// for len(seed) < 32 {
	// 	append(seed, 0)
	// }

	privKey := aldeacrypto.NewKeyFromSeed(seed[:])
	pubKey := privKey.Public()
	// fmt.Println(privKey)
	// xx, _ := pubKey.(aldeacrypto.PublicKey)
	fmt.Println(hex.EncodeToString(pubKey))

	message, _ := hex.DecodeString("18")

	// signature, _ := privKey.Sign(rand.Reader, message[:], crypto.Hash(0))

	signature := aldeacrypto.Sign(aldeacrypto.PrivateKey(privKey), message)
	fmt.Println(hex.EncodeToString(signature))

	expectedSig, _ := hex.DecodeString("7733bfdf2fb51c892ed8e5cf422126c218e52e9f230ef8d33cd090729cc3eae074e38d4737f66d54fab6175b8edd543fa2e07798456a3455d6ce4324b93f0600")
	fmt.Println(bytes.Equal(signature, expectedSig))

	// lets verify

	verified := aldeacrypto.Verify(pubKey, message, signature)
	fmt.Println(verified)
}
