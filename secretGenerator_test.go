package main

import (
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

var (
	failToImportKeyPair = "FAIL_TO_IMPORT"
	failToCreateParam   = "FAIL_TO_CREATE"
	awsError            = awserr.New("error code", "error message", nil)
)

type mockEC2Client struct {
	ec2iface.EC2API
}

func (m *mockEC2Client) ImportKeyPairRequest(input *ec2.ImportKeyPairInput) (*request.Request, *ec2.ImportKeyPairOutput) {
	var err awserr.Error

	if *input.KeyName == failToImportKeyPair {
		err = awsError
	}
	return &request.Request{
		Data:        &ec2.ImportKeyPairOutput{},
		HTTPRequest: &http.Request{Host: "localhost"},
		Error:       err,
	}, &ec2.ImportKeyPairOutput{}
}

type mockSSMClient struct {
	ssmiface.SSMAPI
}

func (m *mockSSMClient) PutParameterRequest(input *ssm.PutParameterInput) (*request.Request, *ssm.PutParameterOutput) {
	var err awserr.Error
	if *input.Name == failToCreateParam {
		err = awsError
	}
	return &request.Request{
		Data:        &ssm.PutParameterOutput{},
		HTTPRequest: &http.Request{Host: "localhost"},
		Error:       err,
	}, &ssm.PutParameterOutput{}
}

// TestCreateSSMParameter ...
func TestCreateSSMParameter(t *testing.T) {
	sg := newSecret(&mockEC2Client{}, &mockSSMClient{})

	t.Run("Test createSSMParameter->Successful", func(t *testing.T) {
		err := sg.createSSMParameter("KeyName", "some secret", "secret description", false)
		if err != nil {
			t.Error("Error : " + err.Error())
			return
		}
	})
	t.Run("Test createSSMParameter->With validation error", func(t *testing.T) {
		sg.validationError = errors.New("Some Problem")
		err := sg.createSSMParameter("KeyName", "some secret", "secret description", false)
		if err == nil {
			t.Error("Error expected")
		}
		if err.Error() != "Some Problem" {
			t.Error("Got an different error")
		}
	})

	t.Run("Test createSSMParameter->Failed To Create Parameter", func(t *testing.T) {
		err := sg.createSSMParameter(failToCreateParam, "some secret", "secret description", false)
		if err == nil {
			t.Error("Error expected")
		}
		if err.Error() != awsError.Error() {
			t.Error("Got an different error")
		}
	})
}

// TestHandleKeyPair ...
func TestHandleKeyPair(t *testing.T) {
	sg := newSecret(&mockEC2Client{}, &mockSSMClient{})

	t.Run("Test handleKeyPair->Successful", func(t *testing.T) {
		event := cfn.Event{
			ResourceType: "Custom::KeyPair",
			ResourceProperties: map[string]interface{}{
				"Name":      "SomeKey",
				"PublicKey": "Somekey",
			}}
		err := sg.validateEvent(event).handleKeyPair()
		if err != nil {
			t.Error("Error : " + err.Error())
		}
	})

	t.Run("Test handleKeyPair->Missing Name", func(t *testing.T) {

		err := sg.validateEvent(cfn.Event{ResourceType: "Custom::KeyPair"}).handleKeyPair()

		if err == nil {
			t.Error("Error expected")
		} else if err.Error() != "Missing required property 'Name'" {
			t.Error("Error expected: Missing required property 'Name'")
		}
	})

	t.Run("Test handleKeyPair->Missing PublicKey", func(t *testing.T) {
		err := sg.validateEvent(cfn.Event{
			ResourceType: "Custom::KeyPair",
			ResourceProperties: map[string]interface{}{
				"Name": "SomeKey",
			}}).handleKeyPair()

		if err == nil {
			t.Error("Error expected")
		} else if err.Error() != "Missing required property 'PublicKey'" {
			t.Error("Error expected: Missing required property 'PublicKey'")
		}
	})

	t.Run("Test handleKeyPair->Failed To Import", func(t *testing.T) {
		event := cfn.Event{
			ResourceType: "Custom::KeyPair",
			ResourceProperties: map[string]interface{}{
				"Name":      failToImportKeyPair,
				"PublicKey": "Somekey",
			}}
		err := sg.validateEvent(event).handleKeyPair()
		if err == nil {
			t.Error("Error expected")
		}
		if err.Error() != awsError.Error() {
			t.Error("Got an different error")
		}
	})
}

//TestHandlePassword ...
func TestHandlePassword(t *testing.T) {
	sg := newSecret(&mockEC2Client{}, &mockSSMClient{})

	t.Run("Test handlePassword->Successful", func(t *testing.T) {
		event := cfn.Event{
			ResourceType: "Custom::Password",
			ResourceProperties: map[string]interface{}{
				"Name": "SomeKey",
			}}
		resp, err := sg.validateEvent(event).handlePassword()
		if err != nil {
			t.Error("Error : " + err.Error())
		}
		if resp.Password == nil {
			t.Error("No password generated")
		}
		if len(*resp.Password) != 30 {
			t.Error("Wrong password length")
		}
	})

	t.Run("Test handlePassword->Missing Name", func(t *testing.T) {
		_, err := sg.validateEvent(cfn.Event{ResourceType: "Custom::Password"}).handlePassword()
		if err == nil {
			t.Error("Error expected")
		} else if err.Error() != "Missing required property 'Name'" {
			t.Error("Error expected: Missing required property 'Name'")
		}
	})

	t.Run("Test handlePassword->Failed To Create Param", func(t *testing.T) {
		event := cfn.Event{
			ResourceType: "Custom::Password",
			ResourceProperties: map[string]interface{}{
				"Name": failToCreateParam,
			}}
		_, err := sg.validateEvent(event).handlePassword()
		if err == nil {
			t.Error("Error expected")
		}
		if err.Error() != awsError.Error() {
			t.Error("Got an different error")
		}
	})
}

//TestHandleRSAKey ...
func TestHandleRSAKey(t *testing.T) {
	sg := newSecret(&mockEC2Client{}, &mockSSMClient{})

	t.Run("Test handleRSAKey->Successful", func(t *testing.T) {

		event := cfn.Event{
			ResourceType: "Custom::RSAKey",
			ResourceProperties: map[string]interface{}{
				"Name": "some",
			}}

		resp, err := sg.validateEvent(event).handleRSAKey()
		if err != nil {
			t.Error("Error : " + err.Error())
		}
		if resp.KeyLength == nil || *resp.KeyLength != 2048 {
			t.Error("The key length does not match the desired value")
		}
		if resp.PrivateKey == nil {
			t.Error("The private key was not created")
		}
		if resp.PublicKey == nil {
			t.Error("The public key was not created")
		}
	})

	t.Run("Test handleRSAKey->Missing Name", func(t *testing.T) {
		_, err := sg.validateEvent(cfn.Event{ResourceType: "Custom::RSAKey"}).handleRSAKey()
		if err == nil {
			t.Error("Error expected")
		} else if err.Error() != "Missing required property 'Name'" {
			t.Error("Error expected: Missing required property 'Name'")
		}
	})

	t.Run("Test handleRSAKey->Failed To Create Param", func(t *testing.T) {
		event := cfn.Event{
			ResourceType: "Custom::RSAKey",
			ResourceProperties: map[string]interface{}{
				"Name": failToCreateParam,
			}}
		_, err := sg.validateEvent(event).handleRSAKey()
		if err == nil {
			t.Error("Error expected")
		}
		if err.Error() != awsError.Error() {
			t.Error("Got an different error")
		}

	})
}

//TestProcess ...
func TestProcess(t *testing.T) {
	sg := newSecret(&mockEC2Client{}, &mockSSMClient{})

	t.Run("TestProcessRSAKey->Successfully", func(t *testing.T) {
		event := cfn.Event{
			ResourceType:       "Custom::RSAKey",
			ResourceProperties: map[string]interface{}{"Name": "RSA_KEY"}}
		id, resp, err := sg.Process(event)
		if err != nil {
			t.Error("Error : " + err.Error())
		}
		if id != "RSAKey:RSA_KEY" {
			t.Error("The id does not match the expected value")
		}
		data, ok := resp["Response"].(responseSecret)
		if !ok {
			t.Error("The response was not created properly")
		} else if data.KeyLength == nil || data.PrivateKey == nil || data.PublicKey == nil {
			t.Error("The response data was not created properly")
		}
	})

	t.Run("TestProcessRSAKey->MissingArgument", func(t *testing.T) {
		_, _, err := sg.Process(cfn.Event{ResourceType: "Custom::RSAKey"})
		if err == nil {
			t.Error("Expected missing parameter error")
		}
	})

	t.Run("TestProcessKeyPair->Successfully", func(t *testing.T) {
		event := cfn.Event{
			ResourceType: "Custom::KeyPair",
			ResourceProperties: map[string]interface{}{
				"Name":      "KEY_PAIR",
				"PublicKey": "PUBLIC_KEY"}}
		id, _, err := sg.Process(event)
		if err != nil {
			t.Error("Error : " + err.Error())
		}
		if id != "KeyPair:KEY_PAIR" {
			t.Error("The id does not match the expected value")
		}
	})

	t.Run("TestProcessKeyPair->MissingArgument", func(t *testing.T) {
		_, _, err := sg.Process(cfn.Event{ResourceType: "Custom::KeyPair"})
		if err == nil {
			t.Error("Expected missing parameter error")
		}
	})

	t.Run("TestProcessPassword->Successfully", func(t *testing.T) {
		event := cfn.Event{
			ResourceType: "Custom::Password",
			ResourceProperties: map[string]interface{}{
				"Name": "PASSWORD"}}
		id, _, err := sg.Process(event)
		if err != nil {
			t.Error("Error : " + err.Error())
		}
		if id != "Password:PASSWORD" {
			t.Error("The id does not match the expected value")
		}
	})

	t.Run("TestProcessPassword->MissingArgument", func(t *testing.T) {
		_, _, err := sg.Process(cfn.Event{ResourceType: "Custom::Password"})
		if err == nil {
			t.Error("Expected missing parameter error")
		}
	})

	t.Run("TestProcess->Unknown", func(t *testing.T) {
		id, _, err := sg.Process(cfn.Event{ResourceType: "Custom::SomethingWrong"})
		if id != "Unknown:Unknown" {
			t.Error("The id does not match the expected value")
		}
		if err == nil {
			t.Error("Expected error")
		} else if err.Error() != "Unknown ResourceType" {
			t.Error("Expected: Unknown ResourceType")
		}
	})

}
