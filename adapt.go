package tfplanadapt

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws"
	"github.com/aquasecurity/defsec/pkg/state"
)

func Adapt(g *Graph) *state.State {
	return &state.State{
		AWS: adaptAWS(g),
	}
}

func adaptAWS(g *Graph) aws.AWS {
	return aws.AWS{
		S3:  adaptS3(g),
		EC2: adaptEC2(g),
	}
}
