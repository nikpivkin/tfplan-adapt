// Terraform Plan is generated from this config

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.34.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.6.0"
    }
  }
}

resource "random_pet" "this" {
  length = 2
}

locals {
  log_bucket_name = "logs-${random_pet.this.id}"
}

module "log_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "= 4.1.0"
  bucket  = local.log_bucket_name

  versioning = {
    enabled = true
    mfa_delete = true
  }

  acl = "aws-exec-read"
}

resource "aws_s3_bucket" "this" {
  bucket = "test"
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}


resource "aws_s3_bucket_logging" "this" {
  bucket = aws_s3_bucket.this.id

  target_bucket = module.log_bucket.s3_bucket_id
  target_prefix = "log/"
}

resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.this.id
  acl    = "public-read"
}

resource "aws_s3_bucket_accelerate_configuration" "example" {
  bucket = aws_s3_bucket.this.id
  status = "Enabled"
}

resource "aws_s3_bucket_lifecycle_configuration" "example" {
  bucket = aws_s3_bucket.this.id

  rule {
    id = "rule-1"
    filter {
      prefix = "logs/"
    }
    status = "Disabled"
  }

  rule {
    id = "rule-2"
    filter {
      prefix = "tmp/"
    }
    status = "Enabled"
  }
}
