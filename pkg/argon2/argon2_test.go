package argon2

import (
	"github.com/google/uuid"
	"log"
	"testing"
	"time"
)

func TestHashPassword(t *testing.T) {
	cases := []struct {
		name    string
		pwd     []byte
		salt    string
		wantErr bool
	}{
		{
			name:    "success",
			pwd:     []byte("some-pwd-ads-poi"),
			salt:    uuid.NewString(),
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			hash := HashPassword(tc.pwd, tc.salt)
			end := time.Now().Sub(start)
			log.Println(hash, end)
		})
	}
}

func TestCompareHashAndPassword(t *testing.T) {
	cases := []struct {
		name    string
		pwd     []byte
		pwd2    []byte
		salt    string
		wantErr bool
	}{
		{
			name:    "success",
			pwd:     []byte("some-pwd-ads-poi"),
			pwd2:    []byte("some-pwd-ads-poi"),
			salt:    uuid.NewString(),
			wantErr: false,
		},
		{
			name:    "mismatch",
			pwd:     []byte("some-pwd-ads-poi"),
			pwd2:    []byte("some-pwd-ads-poy"),
			salt:    uuid.NewString(),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hash := HashPassword(tc.pwd, tc.salt)

			err := CompareHashAndPassword(tc.pwd2, hash, tc.salt)
			if tc.wantErr == false && err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if tc.wantErr == true && err == nil {
				t.Error("expected error, got none")
			}

			log.Println(err)
		})
	}
}
