terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Uses the standard AWS credential chain (env vars, ~/.aws/credentials, or an IAM role) -
# deliberately no custom access-key variables here, unlike the OCI root's explicit
# tenancy/user/fingerprint vars, since AWS's provider already has a well-established
# convention for this that every other AWS Terraform config already relies on.
provider "aws" {
  region = var.aws_region
}
