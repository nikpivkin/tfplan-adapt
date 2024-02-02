package tfplanadapt

import (
	"os"
	"testing"

	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runAdaptTest(t *testing.T, planPath string, expected *state.State) {
	f, err := os.Open(planPath)
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
