# Supported Platforms

## AWS

In order to use Stratus attack techniques against AWS, you need to be authenticated prior to running it. 

Before running an AWS attack technique, Stratus will attempt to call `sts:GetCallerIdentity` and raise an error if this fails.