# Supported Platforms

## AWS

In order to use Stratus Red Team attack techniques against AWS, you need to be authenticated prior to running it. 

Before running an AWS attack technique, Stratus Red Team will attempt to call `sts:GetCallerIdentity` and raise an error if this fails.

## Future Support for Additional Platforms

We plan to add support for [Kubernetes](https://github.com/DataDog/stratus-red-team/issues/51), and one of [Azure](https://github.com/DataDog/stratus-red-team/issues/52) or [GCP](https://github.com/DataDog/stratus-red-team/issues/53) in the future.
If you're interested, go upvote the corresponding issue!