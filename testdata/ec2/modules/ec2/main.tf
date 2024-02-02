resource "aws_instance" "name" {
  launch_template {
    id = var.launch_template
  }
}

variable "launch_template" {
  type = string
}