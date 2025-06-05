package signer

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shinjiru/pkg/jwt/utils"
	"testing"
	"time"
)

func TestSigner_IssueCouple(t *testing.T) {
	kgB := time.Now()
	apk, err := utils.GeneratePrivateKey()
	rpk, err := utils.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("key gen for: ", time.Now().Sub(kgB))

	keyChain := make(map[string]*ecdsa.PublicKey)

	s, err := NewSigner(
		apk,
		rpk,
		600*time.Second,
		7200*time.Second,
		keyChain,
	)
	if err != nil {
		t.Fatal(err)
	}

	itB := time.Now()
	access, refresh, err := s.IssueCouple("tester", uuid.NewString(), make(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("token issue for: ", time.Now().Sub(itB))

	fmt.Println(access, "\n", refresh)
}

func TestSigner_Refresh(t *testing.T) {
	apk, err := utils.GeneratePrivateKey()
	rpk, err := utils.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	keyChain := make(map[string]*ecdsa.PublicKey)

	s, err := NewSigner(
		apk,
		rpk,
		600*time.Second,
		7200*time.Second,
		keyChain,
	)
	if err != nil {
		t.Fatal(err)
	}

	s.keyChain[s.refreshKid] = &s.refreshKey.PublicKey

	access, refresh, err := s.IssueCouple("tester", uuid.NewString(), make(map[string]any))
	if err != nil {
		t.Fatal(err)
	}

	_, refreshToken, err := s.SignCouple(access, refresh)
	if err != nil {
		t.Fatal(err)
	}

	newClaims := &jwt.MapClaims{
		"iss": "tester",
		"sub": refreshToken,
		"exp": jwt.NewNumericDate(time.Now().Add(s.RefreshTTL)),
		"iat": jwt.NewNumericDate(time.Now()),
		"jti": uuid.NewString(),
	}

	trB := time.Now()

	token, err := s.ParseRefresh(refreshToken)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = s.Refresh(token, newClaims)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("refresh tokens for: ", time.Now().Sub(trB))
}
