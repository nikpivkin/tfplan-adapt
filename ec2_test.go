package tfplanadapt

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
)

func TestAdaptEC2(t *testing.T) {

	expected := &state.State{
		AWS: aws.AWS{
			EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						MetadataOptions: ec2.MetadataOptions{
							HttpTokens:   types.String("required", types.Metadata{}),
							HttpEndpoint: types.String("enabled", types.Metadata{}),
						},
						UserData: types.String("some data", types.Metadata{}),
						RootBlockDevice: &ec2.BlockDevice{
							Encrypted: types.Bool(true, types.Metadata{}),
						},
					},
				},
			},
		},
	}

	runAdaptTest(t, filepath.Join("testdata", "ec2", "tfplan.json"), expected)
}
