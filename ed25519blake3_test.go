package ed25519blake3

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/aldeacomputer/ed25519blake3/aldeacrypto"
	"github.com/stretchr/testify/assert"
)

func fileExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else {
		return false
	}
}

func TestAbs(t *testing.T) {
	assert := assert.New(t)
	// path, _ := os.Getwd()
	f, _ := os.Open("./vectors/ed25519-b3.txt")

	buff := make([]byte, 10)
	n, _ := f.Read(buff)
	assert.Equal(n, 10)
	// os.
	scanner := bufio.NewScanner(f)

	// skip the header
	scanner.Scan()

	// iterate lines
	for scanner.Scan() {
		// Extract data from the line of text
		line := scanner.Text()
		chunks := strings.Split(line, ":")
		privKeySeed, _ := hex.DecodeString(chunks[0])
		expectedPubKey, _ := hex.DecodeString(chunks[1])
		message, _ := hex.DecodeString(chunks[2])
		expectedSig, _ := hex.DecodeString(chunks[3])

		// Private key from seed
		privKey := aldeacrypto.NewKeyFromSeed(privKeySeed)
		// Derive pubkey
		pubKey := privKey.Public()

		// Check that pubkey as bytes is the expected one
		assert.Equal([]byte(pubKey), expectedPubKey)

		// Check signature generated
		signature := aldeacrypto.Sign(privKey, message)
		assert.Equal(signature, expectedSig)

		// Check verify
		assert.True(aldeacrypto.Verify(pubKey, message, signature))
	}
}
