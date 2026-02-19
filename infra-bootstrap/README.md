# Bootstrap AWS Infrastructure

This guide walks you through setting up the required AWS infrastructure for the Caution platform in a target AWS account. It creates:

- **S3 bucket** for Terraform state storage (versioned, encrypted)
- **S3 bucket** for storing enclave images (EIFs)
- **DynamoDB table** for Terraform state locking
- **IAM user** with scoped permissions for the Caution platform service

Run this once per AWS account you want to deploy into.

## Prerequisites

- **AWS admin credentials** for the target account
- **AWS CLI** installed and configured
- **OpenTofu** or **Terraform** installed (only needed for this bootstrap step; the platform containers include OpenTofu)

### Verify Prerequisites

**AWS CLI:**

```bash
aws sts get-caller-identity
```

If this fails, see the <a href="https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html" target="_blank">AWS CLI installation and configuration guide</a>.

**OpenTofu or Terraform:**

```bash
tofu --version
# or
terraform --version
```

If not installed, see <a href="https://opentofu.org/docs/intro/install/" target="_blank">OpenTofu installation</a> or <a href="https://developer.hashicorp.com/terraform/install" target="_blank">Terraform installation</a>.

## 1. Configure

Navigate to the bootstrap directory:

```bash
cd infra-bootstrap
```

### Required variables

S3 bucket names must be globally unique. Pass them via `-var` flags or edit `variables.tf`:

| Variable            | Default                | Required to change? | Description                                     |
| ------------------- | ---------------------- | ------------------- | ----------------------------------------------- |
| `state_bucket_name` | `caution-terraform-state` | **Yes**          | S3 bucket for Terraform state (globally unique)  |
| `eif_bucket_name`   | `caution-eif-storage`    | **Yes**          | S3 bucket for enclave images (globally unique)   |
| `aws_region`        | `us-west-2`              | Optional         | AWS region for all resources                     |
| `lock_table_name`   | `terraform-state-lock`   | No               | DynamoDB table name                              |
| `service_user_name` | `caution-platform`       | No               | IAM user name                                    |

A good convention for unique bucket names is to append the account ID:
```
caution-terraform-state-123456789012
caution-eif-storage-123456789012
```

## 2. Run the bootstrap

### Option 1: Using entrypoint script

```bash
./entrypoint.sh
```

The script will check prerequisites, initialize Terraform, show the plan, and ask for confirmation.

### Option 2: Direct Terraform/OpenTofu

If using an AWS profile for a specific account:

```bash
AWS_PROFILE=prod terraform init
AWS_PROFILE=prod terraform apply \
  -var="state_bucket_name=caution-terraform-state-123456789012" \
  -var="eif_bucket_name=caution-eif-storage-123456789012"
```

Or with environment variables:

```bash
export AWS_ACCESS_KEY_ID=your-admin-key
export AWS_SECRET_ACCESS_KEY=your-admin-secret
terraform init
terraform apply \
  -var="state_bucket_name=caution-terraform-state-123456789012" \
  -var="eif_bucket_name=caution-eif-storage-123456789012"
```

## 3. Configure the platform

Go back to the root of the project and set up the `.env` file using the credentials from the bootstrap output:

```bash
cd ..
cp env.example .env
```

Set these values in `.env`:
```
AWS_ACCESS_KEY_ID=<from terraform output>
AWS_SECRET_ACCESS_KEY=<from terraform output>
AWS_ACCOUNT_ID=<target account id>
TERRAFORM_STATE_BUCKET=<your state bucket name>
EIF_S3_BUCKET=<your eif bucket name>
```

To view the credentials after the fact:
```bash
terraform output aws_access_key_id
terraform output aws_secret_access_key
```

You're now ready to run the platform! Return to the [main README](../README.md#run-the-platform) to continue.

## IAM Permissions

The `caution-platform` IAM user is created with these scoped permissions:

- **EC2**: Full (`ec2:*`) for creating/managing VPCs, instances, security groups, etc.
- **IAM**: Create/manage roles and instance profiles scoped to `enclave-*` resources only
- **S3**: Read/write to the Terraform state and EIF storage buckets only
- **DynamoDB**: Read/write to the state lock table only
- **STS**: `GetCallerIdentity` (for Terraform identity checks)

## Destroy

To tear down the bootstrap infrastructure:

```bash
terraform destroy \
  -var="state_bucket_name=caution-terraform-state-123456789012" \
  -var="eif_bucket_name=caution-eif-storage-123456789012"
```

**Warning:** This will delete the S3 buckets (including all Terraform state!) and the DynamoDB table. Only do this if you're completely removing the Caution installation from this account.

## Troubleshooting

**"Bucket name already exists"**

S3 bucket names are globally unique. Use account-ID-suffixed names like `caution-terraform-state-123456789012`.

**"Access Denied" errors**

Ensure you're using admin credentials with full AWS access for the target account. The bootstrap creates IAM users and policies that require elevated permissions.
