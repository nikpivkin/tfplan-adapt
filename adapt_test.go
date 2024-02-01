package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdapt(t *testing.T) {

	expected := &state.State{
		AWS: aws.AWS{
			S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Name: types.String("module.log_bucket.aws_s3_bucket.this[0]", types.Metadata{}),
						PublicAccessBlock: &s3.PublicAccessBlock{
							BlockPublicACLs:       types.Bool(true, types.Metadata{}),
							BlockPublicPolicy:     types.Bool(true, types.Metadata{}),
							RestrictPublicBuckets: types.Bool(true, types.Metadata{}),
							IgnorePublicACLs:      types.Bool(true, types.Metadata{}),
						},
						Versioning: s3.Versioning{
							Enabled:   types.Bool(true, types.Metadata{}),
							MFADelete: types.Bool(true, types.Metadata{}),
						},
						ACL: types.String("aws-exec-read", types.Metadata{}),
					},
					{
						Name: types.String("test", types.Metadata{}),
						Versioning: s3.Versioning{
							Enabled:   types.Bool(true, types.Metadata{}),
							MFADelete: types.Bool(true, types.Metadata{}),
						},
						Encryption: s3.Encryption{
							Enabled:   types.Bool(true, types.Metadata{}),
							Algorithm: types.String("aws:kms", types.Metadata{}),
							KMSKeyId:  types.String("1234abcd-12ab-34cd-56ef-1234567890ab", types.Metadata{}),
						},
						Logging: s3.Logging{
							Enabled:      types.Bool(true, types.Metadata{}),
							TargetBucket: types.String("module.log_bucket.aws_s3_bucket.this[0]", types.Metadata{}),
						},
						PublicAccessBlock: &s3.PublicAccessBlock{
							BlockPublicACLs:       types.Bool(true, types.Metadata{}),
							BlockPublicPolicy:     types.Bool(true, types.Metadata{}),
							RestrictPublicBuckets: types.Bool(true, types.Metadata{}),
							IgnorePublicACLs:      types.Bool(true, types.Metadata{}),
						},
						ACL:                           types.String("public-read", types.Metadata{}),
						AccelerateConfigurationStatus: types.String("Enabled", types.Metadata{}),
						LifecycleConfiguration: []s3.Rules{
							{
								Status: types.String("Disabled", types.Metadata{}),
							},
							{
								Status: types.String("Enabled", types.Metadata{}),
							},
						},
					},
				},
			},
		},
	}

	f, err := os.Open(filepath.Join("testdata", "tfplan1.json"))
	require.NoError(t, err)
	defer f.Close()

	plan, err := ReadPlan(f)
	require.NoError(t, err)

	graph, err := NewTerraformPlanGraph(plan)
	require.NoError(t, err)

	got := Adapt(graph)
	assert.Empty(t, diffState(expected, got))
}

func diffState(expected *state.State, actual *state.State, opts ...cmp.Option) string {
	opts = append(
		opts,
		cmpopts.IgnoreUnexported(state.State{}, types.Metadata{}, types.BaseAttribute{}),
		cmp.AllowUnexported(types.BoolValue{}, types.IntValue{}, types.StringValue{}),
	)

	return cmp.Diff(expected, actual, opts...)
}
