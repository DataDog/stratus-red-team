package aws

import (
	_ "embed"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.exfiltration.ebs-snapshot-downloaded-with-direct-access-api",
		FriendlyName:       "EBS Snapshot Exfiltration Through Direct API",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		Description: `
Exfiltrates an EBS snapshot by using the EBS Direct API.

Warm-up: Creates an EBS volume and a snapshot.

Detonation: Uses the EBS Direct API to access the raw data of the volume.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	// := ebs.NewFromConfig(providers.AWS().GetConnection())

	// Find the snapshot to exfiltrate
	//ourSnapshotId := params["snapshot_id"]

	// Step 1: Put data in our EBS volume
	/*data := "my data!"
	checksum := base64.StdEncoding.EncodeToString(utils.SHA256([]byte(data)))
	_, err := ebsClient.PutSnapshotBlock(context.Background(), &ebs.PutSnapshotBlockInput{
		SnapshotId:        aws.String(ourSnapshotId),
		BlockIndex:        aws.Int32(0),
		DataLength:        aws.Int32(int32(len(data))),
		BlockData:         strings.NewReader(data),
		Checksum:          aws.String(checksum),
		ChecksumAlgorithm: types.ChecksumAlgorithmChecksumAlgorithmSha256,
	})

	if err != nil {
		return err
	}*/
	panic("not implemented")

	return nil
}
