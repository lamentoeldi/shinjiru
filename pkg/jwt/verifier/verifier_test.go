package verifier

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/google/uuid"
	"github.com/shinjiru/pkg/jwt/signer"
	"github.com/shinjiru/pkg/jwt/utils"
	"testing"
	"time"
)

func TestVerifier_VerifyAndExtract(t *testing.T) {
	apk, err := utils.GeneratePrivateKey()
	rpk, err := utils.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	keyChain := make(map[string]*ecdsa.PublicKey)

	s, err := signer.NewSigner(apk, rpk, 600*time.Second, 7200*time.Second, keyChain)
	if err != nil {
		t.Fatal(err)
	}

	access, refresh, err := s.IssueCouple("tester", uuid.NewString(), map[string]any{
		"payload": "test",
	})

	akid, err := utils.GenerateKeyID(&apk.PublicKey)
	rkid, err := utils.GenerateKeyID(&rpk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewVerifier(
		map[string]*ecdsa.PublicKey{
			akid: &apk.PublicKey,
			rkid: &rpk.PublicKey,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	accessToken, _, err := s.SignCouple(access, refresh)

	claims, err := v.VerifyAndExtract(accessToken)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(claims)
}
