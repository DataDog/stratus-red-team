package aws

import (
	_ "embed"
	"encoding/json"
	"errors"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"

	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.initial-access.console-login-without-mfa",
		FriendlyName: "Console Login without MFA",
		Description: `
Simulates a login to the AWS Console for an IAM user without multi-factor authentication (MFA).

Warm-up:

- Create an IAM user
- Create a console profile for this user so it can log in to the AWS Console

Detonation:

- Log in to the AWS Console

References:

- https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/
- https://naikordian.github.io/blog/posts/brute-force-aws-console/
`,
		Detection: `
Using CloudTrail <code>ConsoleLogin</code> event. The field <code>additionalEventData.MFAUser</code> is set to
<code>No</code> when the authentication does not use MFA.

Sample CloudTrail event (redacted for clarity):

` + codeBlock + `json hl_lines="4 14 19 24"
{
	"userIdentity": {
		"session_name": "console-user-wgrosmao",
		"type": "IAMUser",
		"arn": "arn:aws:iam::123456789123:user/console-user-wgrosmao",
		"accountId": "123456789123",
		"userName": "console-user-wgrosmao",
		"principalId": "AIDA254BBSGPKOYEB6PTV"
	},
	"eventSource": "signin.amazonaws.com",
	"eventType": "AwsConsoleSignIn",
	"eventCategory": "Management",
	"awsRegion": "us-east-1",
	"eventName": "ConsoleLogin",
	"readOnly": false,
	"eventTime": "2022-05-30T14:24:34Z",
	"managementEvent": true,
	"additionalEventData": {
		"MFAUsed": "No",
		"LoginTo": "https://console.aws.amazon.com/console/home",
		"MobileVersion": "No"
	},
	"responseElements": {
		"ConsoleLogin": "Success"
	}
}
` + codeBlock + `

Note that for failed console authentication events, the field <code>userIdentity.arn</code> is not set (see https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html#cloudtrail-aws-console-sign-in-events-iam-user-failure).
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		PrerequisitesTerraformCode: tf,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.InitialAccess},
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{
						Name: "Valid Accounts: IAM Users",
						ID:   "T1078.A001",
						URL:  "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1078.A001.html",
					},
				},
			},
		},
		Detonate: detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	// The code to generate a 'ConsoleLogin' event programmatically was inspired from
	// https://naikordian.github.io/blog/posts/brute-force-aws-console/
	// courtesy of Naikordian (naikordian@protonmail.com)

	// Build the HTTP request
	request := buildHttpRequest(params, providers)
	log.Println("Performing a console login for user " + params["username"] + " in account " + params["account_id"])

	// Perform the HTTP request
	response, err := doHttpRequest(request)
	if err != nil {
		return err
	}

	// Parse the response from AWS
	jsonResponse, err := parseAwsResponse(response)
	if err != nil {
		return err
	}

	// AWS returns 'SUCCESS' or 'FAIL' in the 'state' key of the response JSON object
	if jsonResponse["state"] == "SUCCESS" {
		log.Println("Successfully performed a console login!")
	} else {
		return errors.New("unable to authenticate to the AWS Console (received a 'FAIL' response from the authentication endpoint)")
	}

	return nil
}

// buildHttpRequest builds the HTTP request to send to the AWS console sign-in endpoint
func buildHttpRequest(params map[string]string, providers stratus.CloudProviders) *http.Request {
	// https://naikordian.github.io/blog/posts/brute-force-aws-console/
	postData := url.Values{
		"action":       {"iam-user-authentication"},
		"account":      {params["account_id"]},
		"username":     {params["username"]},
		"password":     {params["password"]},
		"client_id":    {"arn:aws:signin:::console/canvas"},
		"redirect_uri": {"https://console.aws.amazon.com/console/home"},
	}

	req, _ := http.NewRequest("POST", "https://signin.aws.amazon.com/authenticate", strings.NewReader(postData.Encode()))

	// Note: You can use the following two lines to intercept the request to AWS through a proxy such as Burp for testing
	// proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	// http.DefaultTransport = &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	req.Header.Add("Referer", "https://signin.aws.amazon.com")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", useragent.GetStratusUserAgentForUUID(providers.AWS().UniqueCorrelationId))

	return req
}

// doHttpRequest performs the HTTP request to the AWS console sign-in endpoint
func doHttpRequest(request *http.Request) (*http.Response, error) {
	// Send the HTTP request to simulate a console login
	httpClient := http.Client{}
	res, err := httpClient.Do(request)
	if err != nil {
		return nil, errors.New("Unable to perform AWS Console login: " + err.Error())
	}

	// Note: The status code is 200 no matter whether the login is successful or not
	if res.StatusCode != 200 {
		return nil, errors.New("Unable to perform AWS Console login (status code " + strconv.Itoa(res.StatusCode) + ")")
	}

	return res, nil
}

// parseAwsResponse parses the response from the AWS console sign-in endpoint and returns an untyped
// map containing the parsed JSON object
func parseAwsResponse(response *http.Response) (map[string]interface{}, error) {
	// Read body and parse JSON response
	resBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.New("Unable to read HTTP response from AWS: " + err.Error())
	}
	var parsedResponse map[string]interface{}
	err = json.Unmarshal(resBytes, &parsedResponse)
	if err != nil {
		return nil, errors.New("Unable to parse HTTP response from AWS: " + err.Error())
	}

	return parsedResponse, nil
}
