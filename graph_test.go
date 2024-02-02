package tfplanadapt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGraph(t *testing.T) {
	graph := NewGraph()

	graph.AddNode(Node{
		resourceType: "aws_s3_bucket",
		resourceName: "this",
		Address:      "aws_s3_bucket.this",
	})

	graph.AddNode(Node{
		resourceType: "aws_s3_bucket",
		resourceName: "log-bucket",
		Address:      "aws_s3_bucket.log-bucket",
	})

	graph.AddNode(Node{
		resourceType: "aws_s3_bucket_logging",
		resourceName: "this",
		Address:      "aws_s3_bucket_logging.this",
	})

	graph.AddEdge("aws_s3_bucket_logging.this", "aws_s3_bucket.this", map[string]string{
		"bucket": "id",
	})
	graph.AddEdge("aws_s3_bucket_logging.this", "aws_s3_bucket.log-bucket", map[string]string{
		"target_bucket": "id",
	})

	thisBucket := graph.GetResource("aws_s3_bucket.this")
	assert.NotNil(t, thisBucket)

	loggingResource := thisBucket.FindBackRelated("aws_s3_bucket_logging", "bucket", "id")
	assert.NotNil(t, loggingResource)

	logBucket := loggingResource.FindRelated("aws_s3_bucket", "target_bucket", "id")
	assert.NotNil(t, logBucket)
}
