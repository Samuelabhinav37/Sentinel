terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Uses the standard AWS credential chain (environment variables,
# ~/.aws/credentials, or an SSO session) - deliberately no custom credential
# variables here, same rationale as the Azure root's ARM_* chain: the AWS
# provider already has a well-established convention every AWS Terraform config
# relies on. Only the region is a variable.
provider "aws" {
  region = var.region
}
