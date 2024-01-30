package main

import (
	"sort"

	"github.com/aquasecurity/defsec/pkg/providers/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(s *PlanState) *state.State {
	return &state.State{
		AWS: adaptAWS(s),
	}
}

func adaptAWS(s *PlanState) aws.AWS {
	return aws.AWS{
		S3: adaptS3(s),
	}
}

func adaptS3(s *PlanState) s3.S3 {
	var buckets []s3.Bucket
	for _, res := range s.GetResourcesByType("aws_s3_bucket") {
		bucket := s3.Bucket{
			Name:           res.GetStringAttr("bucket"),
			BucketLocation: res.GetStringAttr("region"),
		}

		adaptVersioning(s, &bucket, res)
		adaptLogging(s, &bucket, res)
		adaptSSE(s, &bucket, res)
		adaptAccessBlock(s, &bucket, res)
		adaptLifecycleConfiguration(s, &bucket, res)

		if bucketAcl := s.FindBlockByResourceRef(RelatedResourceParams{
			ResourceType:  "aws_s3_bucket_acl",
			ByField:       "bucket",
			To:            res,
			CompareFields: []string{"bucket", "id"},
		}); bucketAcl != nil {
			bucket.ACL = bucketAcl.GetStringAttr("acl")
		}

		if accelerateConfiguration := s.FindBlockByResourceRef(RelatedResourceParams{
			ResourceType:  "aws_s3_bucket_accelerate_configuration",
			ByField:       "bucket",
			To:            res,
			CompareFields: []string{"bucket", "id"},
		}); accelerateConfiguration != nil {
			bucket.AccelerateConfigurationStatus = accelerateConfiguration.GetStringAttr("status")
		}

		buckets = append(buckets, bucket)
	}

	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Name.Value() < buckets[j].Name.Value()
	})
	return s3.S3{
		Buckets: buckets,
	}
}

func adaptVersioning(s *PlanState, bucket *s3.Bucket, res block) {
	versioningAttr := res.GetAttr("versioning")

	bucket.Versioning = s3.Versioning{
		Enabled:   versioningAttr.GetBoolAttr("enabled"),
		MFADelete: versioningAttr.GetBoolAttr("mfa_delete"),
	}

	if bucketVersioning := s.FindBlockByResourceRef(RelatedResourceParams{
		ResourceType:  "aws_s3_bucket_versioning",
		ByField:       "bucket",
		To:            res,
		CompareFields: []string{"bucket", "id"},
	}); bucketVersioning != nil {
		versioningConf := bucketVersioning.GetAttr("versioning_configuration")
		if !versioningConf.IsNil() {
			bucket.Versioning = s3.Versioning{
				Enabled:   types.Bool(versioningConf.GetStringAttr("status").EqualTo("Enabled"), types.Metadata{}),
				MFADelete: types.Bool(versioningConf.GetStringAttr("mfa_delete").EqualTo("Enabled"), types.Metadata{}),
			}
		}
	}
}

func adaptLogging(s *PlanState, bucket *s3.Bucket, res block) {
	if bucketLoggingRes := s.FindBlockByResourceRef(RelatedResourceParams{
		ResourceType:  "aws_s3_bucket_logging",
		ByField:       "bucket",
		To:            res,
		CompareFields: []string{"bucket", "id"},
	}); bucketLoggingRes != nil {
		if logBucket := s.FindBlockByConfigRef(RelatedResourceParams{
			ResourceType:  "aws_s3_bucket",
			ByField:       "target_bucket",
			To:            *bucketLoggingRes,
			CompareFields: []string{"bucket", "id"},
		}); logBucket != nil {
			bucket.Logging = s3.Logging{
				Enabled:      types.Bool(true, types.Metadata{}),
				TargetBucket: logBucket.GetStringAttr("bucket"),
			}
		}
	}
}

func adaptSSE(s *PlanState, bucket *s3.Bucket, res block) {
	// legacy atribute
	applySSE := res.GetNestedAttr("server_side_encryption_configuration.rule.apply_server_side_encryption_by_default")
	if !applySSE.IsNil() {
		kmsKeyIdField := "server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.kms_master_key_id"
		bucket.Encryption = getEncryption(s, applySSE, res, kmsKeyIdField)
	} else if sse := s.FindBlockByResourceRef(RelatedResourceParams{
		ResourceType:  "aws_s3_bucket_server_side_encryption_configuration",
		ByField:       "bucket",
		To:            res,
		CompareFields: []string{"bucket", "id"},
	}); sse != nil {
		if applySSE := sse.GetNestedAttr("rule.apply_server_side_encryption_by_default"); !applySSE.IsNil() {
			kmsKeyIdField := "rule.apply_server_side_encryption_by_default.kms_master_key_id"
			bucket.Encryption = getEncryption(s, applySSE, *sse, kmsKeyIdField)
		}
	}
}

func getEncryption(s *PlanState, attr *attribute, to block, field string) s3.Encryption {
	algorithm := attr.GetStringAttr("sse_algorithm")
	enabled := types.BoolDefault(false, types.Metadata{})
	if algorithm.IsNotEmpty() {
		enabled = types.Bool(true, types.Metadata{})
	}

	kmsKeyID := attr.GetStringAttr("kms_master_key_id")
	if kmsKeyID.IsEmpty() {
		if kmsKeyResource := s.FindBlockByConfigRef(RelatedResourceParams{
			ResourceType:  "aws_kms_key",
			ByField:       field,
			To:            to,
			CompareFields: []string{"arn", "key_id"},
		}); kmsKeyResource != nil {
			// mock ARN
			kmsKeyID = types.String("1234abcd-12ab-34cd-56ef-1234567890ab", types.Metadata{}) // TODO
		}
	}

	return s3.Encryption{
		Enabled:   enabled,
		Algorithm: algorithm,
		KMSKeyId:  kmsKeyID,
	}
}

func adaptAccessBlock(s *PlanState, bucket *s3.Bucket, res block) {
	if accessBlock := s.FindBlockByResourceRef(RelatedResourceParams{
		ResourceType:  "aws_s3_bucket_public_access_block",
		ByField:       "bucket",
		To:            res,
		CompareFields: []string{"bucket", "id"},
	}); accessBlock != nil {
		bucket.PublicAccessBlock = &s3.PublicAccessBlock{
			BlockPublicACLs:       accessBlock.GetBoolAttr("block_public_acls"),
			BlockPublicPolicy:     accessBlock.GetBoolAttr("block_public_policy"),
			IgnorePublicACLs:      accessBlock.GetBoolAttr("ignore_public_acls"),
			RestrictPublicBuckets: accessBlock.GetBoolAttr("restrict_public_buckets"),
		}
	}
}

func adaptLifecycleConfiguration(s *PlanState, bucket *s3.Bucket, res block) {
	if lifecycleCfg := s.FindBlockByResourceRef(RelatedResourceParams{
		ResourceType:  "aws_s3_bucket_lifecycle_configuration",
		ByField:       "bucket",
		To:            res,
		CompareFields: []string{"bucket", "id"},
	}); lifecycleCfg != nil {
		var rules []s3.Rules
		for _, rule := range lifecycleCfg.GetAttr("rule").ToList() {
			rules = append(rules, s3.Rules{
				Status: rule.GetStringAttr("status"),
			})
		}
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Status.Value() < rules[j].Status.Value()
		})
		bucket.LifecycleConfiguration = rules
	}
}
