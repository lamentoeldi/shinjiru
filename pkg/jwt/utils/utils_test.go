package utils

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	pk, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(pk, err)
}

func TestGenerateKeyID(t *testing.T) {
	pk, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	kid, err := GenerateKeyID(pk)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(kid)
}

func TestParsePrivateKey(t *testing.T) {
	pk, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := EncodeKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	pk, err = ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParsePublicKey(t *testing.T) {
	pk, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := EncodeKey(&pk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	public, err := ParsePublicKey(b)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(b), public)
}

func TestParseKeychain(t *testing.T) {
	keychain := make(map[string][]byte)
	for i := 0; i < 5; i++ {
		pk, err := GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}

		kid, err := GenerateKeyID(pk)
		if err != nil {
			t.Fatal(err)
		}

		b, err := EncodeKey(&pk.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		keychain[kid] = b
	}

	b, err := json.Marshal(keychain)
	if err != nil {
		t.Fatal(err)
	}

	kc, err := ParseKeychain(b)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(kc)
}

func TestEncodeKey(t *testing.T) {
	pk, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := EncodeKey(&pk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(b))

	fmt.Println()
}
