package gcp_utils

import (
	"context"
	"errors"
	"fmt"
	"time"
    "google.golang.org/api/iterator"
	"cloud.google.com/go/storage"
	"io/ioutil"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	utils "github.com/datadog/stratus-red-team/v2/internal/utils"
	"google.golang.org/api/cloudresourcemanager/v1"
	"log"
	"os"
	"strings"
)

type BucketObject struct {
	Name 		string 
	Generation 	int64
}


// GCPAssignProjectRole grants a project-wide role to a specific service account
// it works the same as 'gcloud projects add-iam-policy-binding':
// * Step 1: Read the project's IAM policy using [getIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy)
// * Step 2: Create a binding, or add the service account to an existing binding for the role to grant
// * Step 3: Update the project's IAM policy using [setIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy)
func GCPAssignProjectRole(gcp *providers.GCPProvider, principal string, roleToGrant string) error {
	resourceManager, err := cloudresourcemanager.NewService(context.Background(), gcp.Options())
	if err != nil {
		return errors.New("unable to instantiate the GCP cloud resource manager: " + err.Error())
	}

	projectPolicy, err := resourceManager.Projects.GetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return err
	}
	var bindingFound = false
	for _, binding := range projectPolicy.Bindings {
		if binding.Role == roleToGrant {
			bindingFound = true
			log.Println("Adding the principal " + principal + " to an existing binding in the project's IAM policy to grant " + roleToGrant)
			binding.Members = append(binding.Members, principal)
		}
	}
	if !bindingFound {
		log.Println("Creating a new binding in the project's IAM policy to grant " + roleToGrant + " to " + principal)
		projectPolicy.Bindings = append(projectPolicy.Bindings, &cloudresourcemanager.Binding{
			Role:    roleToGrant,
			Members: []string{principal},
		})
	}

	_, err = resourceManager.Projects.SetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.SetIamPolicyRequest{
		Policy: projectPolicy,
	}).Do()

	if err != nil {
		return fmt.Errorf("Failed to update project IAM policy: " + err.Error())
	}
	return nil
}

// GCPUnassignProjectRole un-assigns a project-wide role to a specific service account
// it works the same as 'gcloud projects remove-iam-policy-binding':
// * Step 1: Read the project's IAM policy using [getIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy)
// * Step 2: Remove a binding, or remove the service account from an existing binding for the role to grant
// * Step 3: Update the project's IAM policy using [setIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy)
// Note: no error is returned if the principal does not have a binding in the project's IAM policy
func GCPUnassignProjectRole(gcp *providers.GCPProvider, principal string, roleToRemove string) error {
	resourceManager, err := cloudresourcemanager.NewService(context.Background(), gcp.Options())
	if err != nil {
		return errors.New("unable to instantiate the GCP cloud resource manager: " + err.Error())
	}

	projectPolicy, err := resourceManager.Projects.GetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return errors.New("unable to retrieve the project's IAM policy: " + err.Error())
	}
	var bindingFound = false
	for _, binding := range projectPolicy.Bindings {
		if binding.Role == roleToRemove {
			index := utils.IndexOf(binding.Members, principal)
			if index > -1 {
				bindingFound = true
				binding.Members = utils.Remove(binding.Members, index)
			}
		}
	}
	if bindingFound {
		log.Println("Updating project's IAM policy to remove reference to the principal " + principal + " for role " + roleToRemove)
		_, err := resourceManager.Projects.SetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.SetIamPolicyRequest{
			Policy: projectPolicy,
		}).Do()
		if err != nil {
			return errors.New("failed to update project IAM policy: " + err.Error())
		}
		return nil
	}

	// no reference to the principal in the project's IAM policy, we're good to go - nothing to do
	return nil
}

const DefaultFictitiousAttackerEmail = "stratusredteam@gmail.com"

func GetAttackerPrincipal() string {
	const UserPrefix = "user:"
	if attackerEmail := os.Getenv(utils.AttackerEmailEnvVarKey); attackerEmail != "" {
		return UserPrefix + strings.ToLower(attackerEmail)
	} else {
		return UserPrefix + DefaultFictitiousAttackerEmail
	}
}

// ListAllObjectVersions lists all objects in a bucket and their versions
// it works the same as `gsutil ls -a 'gs://<bucketName>/'`
func ListAllObjectVersions(bucket *storage.BucketHandle, ctx context.Context) ([]BucketObject,error) {
	ctx, cancel := context.WithTimeout(ctx, 10 * time.Second)
	defer cancel()

	// list the objects
	var result []BucketObject 
	it := bucket.Objects(ctx, &storage.Query{
		Versions: true,
	})

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("unable to list bucket objects: %w", err)
		}
		result = append(result, BucketObject{
			Name: attrs.Name,
			Generation: attrs.Generation,
		})
	}

	return result, nil
}

// DownloadAllObjects downloads all objects from a GCS bucket
// it works the same as `gsutil -m cp -r 'gs://<bucketName>/*' .`
func DownloadAllObjects(bucket *storage.BucketHandle, ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 50 * time.Second)
	defer cancel()

	// enumerate all files
	it := bucket.Objects(ctx, nil)
    for {
        attrs, err := it.Next()
        if err == iterator.Done {
            break 
        }
        if err != nil {
            return fmt.Errorf("unable to list bucket objects: %w", err)
        }

        // create reader
        reader, err := bucket.Object(attrs.Name).NewReader(ctx)
        if err != nil {
            return fmt.Errorf("unable to read the object")
        }
        defer reader.Close()

        // read the content
        if _, err := ioutil.ReadAll(reader); err != nil {
            return fmt.Errorf("unable to read data from bucket: " + err.Error())
        }
    }

    log.Println("successfully downloaded all objects from the bucket")
    return nil 
}

// UploadFile uploads a file into a GCS bucket
// it works the same as `gsutil cp <local_file> gs://<bucketName>/<remote_file>`
func UploadFile(bucketName string, fileName string, content []byte) (int64,error) {
	ctx := context.Background()

	// create bucket client
    client, err := storage.NewClient(ctx)
    if err != nil {
        return 0,errors.New("unable to create new client")
    }
    defer client.Close()

    // write bucket object
    bucket := client.Bucket(bucketName)
    return WriteBucketObject(bucket, ctx, fileName, content) 
}

// WriteBucketObject writes something into a GCS bucket
func WriteBucketObject(bucket *storage.BucketHandle, ctx context.Context, filename string, content []byte) (int64,error) {
	ctx, cancel := context.WithTimeout(ctx, 50 * time.Second)
	defer cancel()

	// create bucket object
	obj := bucket.Object(filename)

	// write object to bucket
	writer := obj.NewWriter(ctx)
	if _, err := writer.Write(content); err != nil {
		return 0, errors.New("unable to write object: " + err.Error())
    }
    writer.Close()

    // get the generation number
    attrs, err := obj.Attrs(ctx)
    return attrs.Generation, err 
}