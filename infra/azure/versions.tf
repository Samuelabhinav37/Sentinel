terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

# Uses the standard Azure credential chain (az login's cached session, or ARM_*
# env vars for a service principal: ARM_SUBSCRIPTION_ID, ARM_TENANT_ID, ARM_CLIENT_ID,
# ARM_CLIENT_SECRET) - deliberately no custom credential variables here, unlike the OCI
# root's explicit tenancy/user/fingerprint vars, since azurerm's provider already has a
# well-established convention for this that every other Azure Terraform config relies on.
provider "azurerm" {
  features {}
}
