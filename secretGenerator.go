package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"encoding/pem"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"golang.org/x/crypto/ssh"
)

type secretGenerator struct {
	EC2Client       ec2iface.EC2API
	SSMClient       ssmiface.SSMAPI
	Name            string
	publicKey       *string
	alphabet        string
	passwordLength  int
	validationError error
}

type responseSecret struct {
	KeyLength  *int    `json:"key_length"`
	PrivateKey *string `json:"private_key"`
	PublicKey  *string `json:"public_key"`
	Password   *string `json:"password"`
}

func newSecret(ec2Client ec2iface.EC2API, ssmClient ssmiface.SSMAPI) *secretGenerator {
	return &secretGenerator{
		EC2Client: ec2Client,
		SSMClient: ssmClient,
	}
}

func (sg *secretGenerator) validateEvent(event cfn.Event) *secretGenerator {
	trg := &secretGenerator{
		SSMClient: sg.SSMClient,
		EC2Client: sg.EC2Client}
	keyName, ok := event.ResourceProperties["Name"].(string)
	if !ok {
		trg.validationError = errors.New("Missing required property 'Name'")
		keyName = "Unknown"
	}
	trg.Name = keyName
	publicKey, ok := event.ResourceProperties["PublicKey"].(string)
	if ok {
		trg.publicKey = &publicKey
	}
	alphabet, ok := event.ResourceProperties["Alphabet"].(string)
	if !ok {
		alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+-[]?;,."
	}
	trg.alphabet = alphabet
	length, ok := event.ResourceProperties["Length"].(int)
	if !ok {
		length = 30
	}
	trg.passwordLength = length

	return trg
}

func (sg *secretGenerator) Process(event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	sg = sg.validateEvent(event)
	data = map[string]interface{}{
		"Response": nil,
	}
	var response *responseSecret
	switch event.ResourceType {
	case "Custom::RSAKey":
		response, err = sg.handleRSAKey()
		physicalResourceID = "RSAKey:" + sg.Name
	case "Custom::KeyPair":
		err = sg.handleKeyPair()
		physicalResourceID = "KeyPair:" + sg.Name

	case "Custom::Password":
		response, err = sg.handlePassword()
		physicalResourceID = "Password:" + sg.Name

	default:
		err = errors.New("Unknown ResourceType")
		physicalResourceID = "Unknown:" + sg.Name
	}

	if response != nil {
		data = map[string]interface{}{
			"Response": *response,
		}
	}

	return
}

func (sg *secretGenerator) handleRSAKey() (*responseSecret, error) {

	if sg.validationError != nil {
		return nil, sg.validationError
	}
	keyLength := 2048

	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	publicKeyRSA, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	publicKey := ssh.MarshalAuthorizedKey(publicKeyRSA)

	privateBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey)}

	privatePEM := pem.EncodeToMemory(&privateBlock)

	resPrivateKey := string(privatePEM)
	resPublicKey := string(publicKey)

	err = sg.createSSMParameter(sg.Name, resPrivateKey, "RSA private key", false)

	return &responseSecret{
		KeyLength:  &keyLength,
		PrivateKey: &resPrivateKey,
		PublicKey:  &resPublicKey}, err
}

func (sg *secretGenerator) handleKeyPair() error {

	if sg.validationError != nil {
		return sg.validationError
	}
	if sg.publicKey == nil {
		sg.validationError = errors.New("Missing required property 'PublicKey'")
		return sg.validationError
	}

	req, _ := sg.EC2Client.ImportKeyPairRequest(&ec2.ImportKeyPairInput{
		KeyName:           aws.String(sg.Name),
		PublicKeyMaterial: []byte(*sg.publicKey),
	})
	return req.Send()
}

func (sg *secretGenerator) handlePassword() (*responseSecret, error) {
	if sg.validationError != nil {
		return nil, sg.validationError
	}
	buff := make([]byte, sg.passwordLength)
	_, err := rand.Read(buff)
	if err != nil {
		return nil, err
	}
	l := len(sg.alphabet)
	for i, b := range buff {
		buff[i] = sg.alphabet[b%byte(l)]
	}
	password := string(buff)

	err = sg.createSSMParameter(sg.Name, password, "Password", false)

	return &responseSecret{Password: &password}, err
}

func (sg *secretGenerator) createSSMParameter(key, value, description string, override bool) error {
	if sg.validationError != nil {
		return sg.validationError
	}
	req, _ := sg.SSMClient.PutParameterRequest(&ssm.PutParameterInput{
		Description: aws.String(description),
		Name:        aws.String(key),
		Type:        aws.String(ssm.ParameterTypeSecureString),
		Value:       aws.String(value),
		Overwrite:   aws.Bool(override),
	})
	return req.Send()
}
