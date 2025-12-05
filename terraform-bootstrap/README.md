# Terraform Bootstrap

This bootstraps the initial AWS infrastructure required for running the Caution platform. It creates:

- **S3 bucket** for Terraform state storage (versioned, encrypted)
- **DynamoDB table** for Terraform state locking
- **IAM user** with limited permissions for the Caution API service

## Prerequisites

1. **AWS root or admin credentials** - You need full admin access to create these resources
2. **AWS Organizations enabled** - The bootstrap checks for this and will fail if not enabled
3. **AWS CLI** installed and configured
4. **OpenTofu or Terraform** installed (if running directly)

### Enable AWS Organizations (if not already enabled)

1. Go to https://console.aws.amazon.com/organizations/
2. Click "Create Organization"
3. Choose "Enable all features"

## Configuration

Edit `variables.tf` to customize (or override via `-var` flags):

| Variable | Default | Description |
|----------|---------|-------------|
| `aws_region` | `us-west-2` | AWS region for all resources |
| `state_bucket_name` | `caution-terraform-state` | S3 bucket name (must be globally unique!) |
| `lock_table_name` | `terraform-state-lock` | DynamoDB table name |
| `service_user_name` | `caution-terraform-service` | IAM user name |

**Important:** S3 bucket names must be globally unique across all AWS accounts. Change `state_bucket_name` to something unique like `mycompany-caution-terraform-state`.

## First-Time Setup (Important!)

The `backend.tf` file configures remote state storage, but creates a chicken-and-egg problem: the S3 bucket doesn't exist yet on first run.

**For first-time setup, temporarily rename or delete `backend.tf`:**

```bash
mv backend.tf backend.tf.disabled
```

After the bootstrap completes successfully, restore it:

```bash
mv backend.tf.disabled backend.tf
```

Then migrate the local state to S3:

```bash
tofu init -migrate-state
# or: terraform init -migrate-state
```

## Running the Bootstrap

### Option 1: Direct execution (recommended for first-time setup)

```bash
cd terraform-bootstrap

# Ensure AWS credentials are configured
aws sts get-caller-identity

# Run the bootstrap script
./entrypoint.sh
```

The script will:
1. Check for AWS CLI and Terraform/OpenTofu
2. Verify AWS credentials and Organizations access
3. Initialize Terraform
4. Show the plan and ask for confirmation
5. Apply the configuration
6. Output and save the new IAM credentials

### Option 2: Container execution

```bash
cd terraform-bootstrap

# Set AWS credentials
export AWS_ACCESS_KEY_ID=your-admin-key
export AWS_SECRET_ACCESS_KEY=your-admin-secret

# Run via container
./run.sh apply
```

Or if you have `~/.aws` configured, the script will mount that automatically.

## Outputs

After successful execution:

1. **Console output** displays the new IAM credentials
2. **`outputs.json`** contains all outputs in JSON format
3. **`../aws-credentials.env`** contains credentials in shell-sourceable format:

```bash
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-west-2
TERRAFORM_STATE_BUCKET=<YOUR_BUCKET_NAME>
```

## Created IAM Permissions

The service IAM user has these permissions:

- **Organizations**: Create accounts, describe accounts/organization, list accounts
- **S3**: Read/write to the Terraform state bucket only
- **DynamoDB**: Read/write to the state lock table only

This follows the principle of least privilege - the service user cannot access other AWS resources.

## Next Steps

Go back to the root of the project and make sure you set up the `.env` file based on the `.example.env` file.

## Destroying the Bootstrap

To tear down the bootstrap infrastructure:

```bash
tofu destroy
# or: terraform destroy
```

**Warning:** This will delete the S3 bucket (including all Terraform state!) and the DynamoDB table. Only do this if you're completely removing the Caution installation.

## Troubleshooting

### "Bucket name already exists"

S3 bucket names are globally unique. Change `state_bucket_name` in `variables.tf` to something unique.

### "AWS Organizations not enabled"

Follow the instructions in Prerequisites to enable AWS Organizations.

### "Access Denied" errors

Ensure you're using root or admin credentials with full AWS access. The bootstrap creates resources that require elevated permissions.

### Backend initialization fails

If you see errors about the S3 backend not existing, you're hitting the chicken-and-egg problem. See "First-Time Setup" above.