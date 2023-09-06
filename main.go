package main

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	"crypto/x509"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

const (
	rsaBlockStr = "RSA PUBLIC KEY"
	bits        = 4096
)

func main() {
	var privateKeyFile string
	var kubeconfigFile string
	var timestamp string
	flag.StringVar(&privateKeyFile, "private", "", "path to your private key file")
	flag.StringVar(&kubeconfigFile, "kubeconfig", "", "path to your gpg encrypted kubeconfig")
	flag.StringVar(&timestamp, "timestamp", "", "timestamp in rf3339 format ex. 2023-09-05T09:23:06Z")
	flag.Parse()
	layout := time.RFC3339
	tm, err := time.Parse(layout, timestamp)
	if err != nil {
		log.Printf("unable to read timestamp   :%s", err.Error())
	}
	kubeconfigStr, err := os.ReadFile(kubeconfigFile)
	if err != nil {
		log.Printf("unable to read kubeconfig key file  :%s", privateKeyFile)
	}
	priv, err := os.ReadFile(privateKeyFile)
	if err != nil {
		log.Printf("unable to read private key file  :%s", privateKeyFile)
	}
	privPem, _ := pem.Decode(priv)
	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		log.Printf("RSA private key is of the wrong type :%s", privPem.Type)
	}
	privPemBytes = privPem.Bytes

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		log.Printf("Unable to parse RSA private key :%s", err.Error())
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Printf("Unable to parse RSA private key : %s", err.Error())
	}

	kubeconfig, err := decryptString(string(kubeconfigStr), privateKey, &tm)
	if err != nil {
		log.Fatalf("failed to decrypt the kubeconfig: %v", err)
	}
	fmt.Println(kubeconfig)
}

func decryptString(encString string, priv *rsa.PrivateKey, tm *time.Time) (string, error) {
	tim := time.Unix(tm.Unix(), int64(int32(tm.Nanosecond())))
	publicKey := packet.NewRSAPublicKey(tim, &priv.PublicKey)
	privateKey := packet.NewRSAPrivateKey(tim, priv)
	entity := createEntityFromKeys(publicKey, privateKey)
	var entityList openpgp.EntityList
	entityList = append(entityList, entity)

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)
	return decStr, nil
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: bits,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}
