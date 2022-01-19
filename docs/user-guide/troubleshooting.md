# Troubleshooting

## "*You are not authenticated against AWS, or you have not set your region.*"

You must be authenticated to AWS before running Stratus Red Team. Typically, you must be able to run `aws sts get-caller-identity` in your shell before running Stratus Red Team.

## "*The argument "region" is required, but no definition was found*"

This is a Terraform error indicating you did not set `AWS_REGION`. Set it using:

```bash
export AWS_REGION=us-east-1
```