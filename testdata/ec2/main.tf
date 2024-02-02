module "ec2" {
  source = "./modules/ec2"
  launch_template = aws_launch_template.this.id
}


resource "aws_launch_template" "this" {
  name = "test_launch_template"

  user_data = "some data"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

resource "aws_ebs_encryption_by_default" "example" {
  enabled = true
}