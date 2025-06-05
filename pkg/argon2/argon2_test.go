package argon2

import (
	"github.com/google/uuid"
	"log"
	"testing"
	"time"
)

func TestMakePasswordString(t *testing.T) {
	cases := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{
			name:    "success",
			length:  16,
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pwd := makePasswordString(tc.length)
			log.Println(pwd)
		})
	}
}

func TestHashPassword(t *testing.T) {
	cases := []struct {
		name    string
		pwd     string
		salt    string
		wantErr bool
	}{
		{
			name:    "success",
			pwd:     "some-pwd-ads-poi",
			salt:    uuid.NewString(),
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			hash := hashPassword(tc.pwd, tc.salt)
			end := time.Now().Sub(start)
			log.Println(hash, end)
		})
	}
}

func TestGeneratePasswordWithHash(t *testing.T) {
	cases := []struct {
		name   string
		length int
		salt   string
	}{
		{
			name:   "success",
			length: 16,
			salt:   uuid.NewString(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pwd, hash := GeneratePasswordWithHash(tc.length, tc.salt)
			log.Println(pwd, hash)
		})
	}
}

func TestCompareHashAndPassword(t *testing.T) {
	cases := []struct {
		name    string
		pwd     string
		pwd2    string
		salt    string
		wantErr bool
	}{
		{
			name:    "success",
			pwd:     "some-pwd-ads-poi",
			pwd2:    "some-pwd-ads-poi",
			salt:    uuid.NewString(),
			wantErr: false,
		},
		{
			name:    "mismatch",
			pwd:     "some-pwd-ads-poi",
			pwd2:    "some-pwd-ads-poy",
			salt:    uuid.NewString(),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hash := hashPassword(tc.pwd, tc.salt)

			err := CompareHashAndPassword(tc.pwd2, tc.salt, hash)
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
