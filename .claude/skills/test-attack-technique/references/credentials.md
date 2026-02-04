# Cloud Credentials Validation Reference

This document provides detailed instructions for validating cloud credentials before executing Stratus Red Team attack techniques.

## Overview

Before running any attack technique, you must validate that the correct cloud credentials are configured and get explicit user confirmation. Each cloud provider has different commands for checking current credentials.

## AWS (Amazon Web Services)

### Validation Command
```bash
aws sts get-caller-identity
```

### Expected Output Format
```json
{
    "UserId": "AIDAI************",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/username"
}
```

### Information to Present to User
- **Account ID**: The AWS account number
- **User/Role ARN**: The full ARN of the identity
- **User ID**: The unique identifier

### Presentation Format
```
Current AWS credentials:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Account:  123456789012
Identity: arn:aws:iam::123456789012:user/username
User ID:  AIDAI************

These credentials will be used to create resources and execute the attack.
```

### Changing Credentials
If the user needs to change credentials:
```bash
# Configure AWS credentials
aws configure

# Or use environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...  # if using temporary credentials

# Or use AWS profiles
export AWS_PROFILE=test-profile
```

---

## Azure

### Validation Command
```bash
az account show
```

### CRITICAL: Set Subscription ID Environment Variables
Before running any stratus commands (warmup, detonate, cleanup), you MUST export the subscription IDs:
```bash
export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export ARM_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID
```

Or manually:
```bash
export AZURE_SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export ARM_SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Terraform (used by stratus) requires these environment variables to determine which Azure subscription to use. AZURE_SUBSCRIPTION_ID is used by Azure SDK, and ARM_SUBSCRIPTION_ID is used by Terraform's Azure provider.

### Expected Output Format
```json
{
  "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "name": "Subscription Name",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "user": {
    "name": "user@example.com",
    "type": "user"
  }
}
```

### Information to Present to User
- **Subscription Name**: Human-readable subscription name
- **Subscription ID**: The subscription GUID
- **User**: The authenticated user email
- **Tenant ID**: The Azure AD tenant

### Presentation Format
```
Current Azure credentials:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Subscription: Subscription Name (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
User:         user@example.com
Tenant:       xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

The AZURE_SUBSCRIPTION_ID and ARM_SUBSCRIPTION_ID environment variables will be exported before running stratus commands.
These credentials will be used to create resources and execute the attack.
```

### Changing Credentials
If the user needs to change credentials:
```bash
# List available subscriptions
az account list

# Switch to a different subscription
az account set --subscription "subscription-name-or-id"

# Login with different credentials
az login

# Login with service principal
az login --service-principal -u <app-id> -p <password-or-cert> --tenant <tenant>
```

---

## GCP (Google Cloud Platform)

### Validation Commands
```bash
# Get current project
gcloud config get-value project

# Get authenticated accounts
gcloud auth list
```

### Expected Output Format
```
# Project output
my-project-id

# Auth list output
       Credentialed Accounts
ACTIVE  ACCOUNT
*       user@example.com
```

### Information to Present to User
- **Project ID**: The active GCP project
- **Account**: The authenticated Google account (marked with *)

### Presentation Format
```
Current GCP credentials:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Project: my-project-id
Account: user@example.com (active)

These credentials will be used to create resources and execute the attack.
```

### Changing Credentials
If the user needs to change credentials:
```bash
# Set different project
gcloud config set project PROJECT_ID

# Authenticate with different account
gcloud auth login

# Use service account
gcloud auth activate-service-account --key-file=KEY_FILE

# List available projects
gcloud projects list
```

---

## Kubernetes

### Validation Commands
```bash
# Get current context
kubectl config current-context

# Get context details
kubectl config view --minify
```

### Expected Output Format
```
# Current context
minikube

# Context details
apiVersion: v1
clusters:
- cluster:
    server: https://192.168.49.2:8443
  name: minikube
contexts:
- context:
    cluster: minikube
    namespace: default
    user: minikube
  name: minikube
current-context: minikube
```

### Information to Present to User
- **Context Name**: The active kubectl context
- **Cluster**: The target cluster name/server
- **Namespace**: The active namespace
- **User**: The authenticated user/service account

### Presentation Format
```
Current Kubernetes credentials:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Context:   minikube
Cluster:   https://192.168.49.2:8443
Namespace: default
User:      minikube

These credentials will be used to create resources and execute the attack.
```

### Changing Credentials
If the user needs to change credentials:
```bash
# List available contexts
kubectl config get-contexts

# Switch context
kubectl config use-context CONTEXT_NAME

# Set default namespace
kubectl config set-context --current --namespace=NAMESPACE
```

---

## Entra ID (formerly Azure AD)

### Validation Command
```bash
az ad signed-in-user show
```

### Expected Output Format
```json
{
  "userPrincipalName": "user@example.com",
  "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "displayName": "User Name"
}
```

### Information to Present to User
- **User Principal Name**: The authenticated user's email/UPN
- **Object ID**: The user's unique identifier
- **Display Name**: The user's display name

### Presentation Format
```
Current Entra ID credentials:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
User:        User Name (user@example.com)
Object ID:   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

These credentials will be used to execute the attack technique.
```

### Changing Credentials
If the user needs to change credentials:
```bash
# Login with different account
az login

# Login with service principal
az login --service-principal -u <app-id> -p <password-or-cert> --tenant <tenant>
```

---

## Error Handling

### Command Not Found
If the cloud CLI is not installed:
- **AWS**: Install AWS CLI - https://aws.amazon.com/cli/
- **Azure**: Install Azure CLI - https://docs.microsoft.com/cli/azure/install-azure-cli
- **GCP**: Install gcloud SDK - https://cloud.google.com/sdk/docs/install
- **Kubernetes**: Install kubectl - https://kubernetes.io/docs/tasks/tools/

### Not Authenticated
If credentials are not configured:
- Show the error message from the CLI
- Provide instructions for authentication (see "Changing Credentials" sections above)
- Do not proceed with the attack technique

### Multiple Identities
If multiple accounts/subscriptions/projects are available:
- Show all available options
- Indicate which one is currently active
- Ask user to confirm or switch before proceeding

---

## Security Best Practices

1. **Never log or store credentials**: Only display account identifiers, never actual secrets
2. **Verify before execution**: Always get explicit user confirmation before proceeding
3. **Test environments only**: Warn users to only use test/development environments
4. **Principle of least privilege**: Recommend using credentials with minimal required permissions
5. **Temporary credentials**: Prefer temporary/session credentials over long-term credentials
6. **Audit logs**: Remind users that all actions will be logged in cloud audit logs

---

## Implementation Notes for Claude

When validating credentials:

1. **Run the appropriate command** based on the technique platform
2. **Capture and parse the output** into structured information
3. **Format for readability** using the presentation formats above
4. **Handle errors gracefully** if CLI is missing or credentials aren't configured
5. **Use AskUserQuestion** to get explicit confirmation before proceeding
6. **Include credential summary** in the HTML report (account IDs only, never secrets)

Example confirmation question:
```
Do you want to proceed with these credentials?
- Yes, proceed with this AWS account
- No, I need to change credentials first
```

If the user selects "No":
- Show instructions for changing credentials (from sections above)
- Exit gracefully
- Suggest re-running the skill after configuring credentials
