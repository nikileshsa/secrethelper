package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ssm"
)

var (
	ses       *session.Session
	ec2Client *ec2.EC2
	ssmClient *ssm.SSM
)

func init() {
	ses := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	ec2Client = ec2.New(ses)
	ssmClient = ssm.New(ses)
}

func handler(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	return newSecret(ec2Client, ssmClient).Process(event)
}

func main() {
	_, resp, err := handler(nil, cfn.Event{
		ResourceType:       "Custom::RSAKey",
		ResourceProperties: map[string]interface{}{"Name": "/KEY_RSA"}})
	if err != nil {
		fmt.Println(err)
		return
	}
	data, ok := resp["Response"].(responseSecret)
	if ok {
		publicKey := *data.PublicKey
		_, resp, err = handler(nil, cfn.Event{
			ResourceType: "Custom::KeyPair",
			ResourceProperties: map[string]interface{}{
				"Name":      "KEYSSM",
				"PublicKey": publicKey,
			}})
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Print(resp["Response"])
	}
	lambda.Start(cfn.LambdaWrap(handler))
}
