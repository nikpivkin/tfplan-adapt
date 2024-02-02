package tfplanadapt

import (
	"sort"

	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/types"
)

func adaptS3(g *Graph) s3.S3 {
	var buckets []s3.Bucket
	for _, res := range g.FindResourcesByType("aws_s3_bucket") {
		bucket := s3.Bucket{
			Name:           res.GetStringAttr("bucket", res.ID()),
			BucketLocation: res.GetStringAttr("region"),
		}

		adaptVersioning(&bucket, res)
		adaptLogging(&bucket, res)
		adaptSSE(&bucket, res)
		adaptAccessBlock(&bucket, res)
		adaptLifecycleConfiguration(&bucket, res)

		if bucketAcl := res.FindBackRelated("aws_s3_bucket_acl", "bucket", "bucket", "id"); bucketAcl != nil {
			bucket.ACL = bucketAcl.GetStringAttr("acl")
		}

		if accelerateConfiguration := res.FindBackRelated(
			"aws_s3_bucket_accelerate_configuration", "bucket", "bucket", "id",
		); accelerateConfiguration != nil {
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

func adaptVersioning(bucket *s3.Bucket, res *Node) {
	versioningAttr := res.GetAttr("versioning")

	bucket.Versioning = s3.Versioning{
		Enabled:   versioningAttr.GetBoolAttr("enabled"),
		MFADelete: versioningAttr.GetBoolAttr("mfa_delete"),
	}

	if bucketVersioning := res.FindBackRelated(
		"aws_s3_bucket_versioning", "bucket", "bucket", "id",
	); bucketVersioning != nil {
		versioningConf := bucketVersioning.GetAttr("versioning_configuration")
		if !versioningConf.IsNil() {
			bucket.Versioning = s3.Versioning{
				Enabled:   types.Bool(versioningConf.GetStringAttr("status").EqualTo("Enabled"), types.Metadata{}),
				MFADelete: types.Bool(versioningConf.GetStringAttr("mfa_delete").EqualTo("Enabled"), types.Metadata{}),
			}
		}
	}
}

func adaptLogging(bucket *s3.Bucket, res *Node) {
	if bucketLoggingRes := res.FindBackRelated(
		"aws_s3_bucket_logging", "bucket", "bucket", "id",
	); bucketLoggingRes != nil {
		if logBucket := bucketLoggingRes.FindRelated(
			"aws_s3_bucket", "target_bucket", "bucket", "id",
		); logBucket != nil {
			bucket.Logging = s3.Logging{
				Enabled:      types.Bool(true, types.Metadata{}),
				TargetBucket: logBucket.GetStringAttr("bucket", logBucket.ID()),
			}
		}
	}
}

func adaptSSE(bucket *s3.Bucket, res *Node) {
	// legacy atribute
	applySSE := res.GetNestedAttr("server_side_encryption_configuration.rule.apply_server_side_encryption_by_default")
	if !applySSE.IsNil() {
		kmsKeyIdField := "server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.kms_master_key_id"
		bucket.Encryption = getEncryption(applySSE, res, kmsKeyIdField)
	} else if sse := res.FindBackRelated(
		"aws_s3_bucket_server_side_encryption_configuration", "bucket", "bucket", "id",
	); sse != nil {
		if applySSE := sse.GetNestedAttr("rule.apply_server_side_encryption_by_default"); !applySSE.IsNil() {
			kmsKeyIdField := "rule.apply_server_side_encryption_by_default.kms_master_key_id"
			bucket.Encryption = getEncryption(applySSE, sse, kmsKeyIdField)
		}
	}
}

func getEncryption(attr *Attribute, to *Node, field string) s3.Encryption {
	algorithm := attr.GetStringAttr("sse_algorithm")
	enabled := types.BoolDefault(false, types.Metadata{})
	if algorithm.IsNotEmpty() {
		enabled = types.Bool(true, types.Metadata{})
	}

	kmsKeyID := attr.GetStringAttr("kms_master_key_id")
	if kmsKeyID.IsEmpty() {
		if kmsKeyResource := to.FindRelated("aws_kms_key", field, "kms_key_id", "arn"); kmsKeyResource != nil {
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

func adaptAccessBlock(bucket *s3.Bucket, res *Node) {
	if accessBlock := res.FindBackRelated(
		"aws_s3_bucket_public_access_block", "bucket", "bucket", "id",
	); accessBlock != nil {
		bucket.PublicAccessBlock = &s3.PublicAccessBlock{
			BlockPublicACLs:       accessBlock.GetBoolAttr("block_public_acls"),
			BlockPublicPolicy:     accessBlock.GetBoolAttr("block_public_policy"),
			IgnorePublicACLs:      accessBlock.GetBoolAttr("ignore_public_acls"),
			RestrictPublicBuckets: accessBlock.GetBoolAttr("restrict_public_buckets"),
		}
	}
}

func adaptLifecycleConfiguration(bucket *s3.Bucket, res *Node) {
	if lifecycleCfg := res.FindBackRelated(
		"aws_s3_bucket_lifecycle_configuration", "bucket", "bucket", "id",
	); lifecycleCfg != nil {
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
