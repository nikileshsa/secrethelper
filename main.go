package main

import (
	"context"

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
	lambda.Start(cfn.LambdaWrap(handler))
}
