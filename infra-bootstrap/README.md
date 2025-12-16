# Bootstrap AWS Infrastructure

This guide walks you through setting up the required AWS infrastructure for the Caution platform. It creates:

- **S3 bucket** for Terraform state storage (versioned, encrypted)
- **S3 bucket** for storing enclave images (EIFs)
- **DynamoDB table** for Terraform state locking
- **IAM user** with permissions for the Caution API service

## Prerequisites

- **AWS root or admin credentials** - You need full admin access to create these resources
- **AWS CLI** installed and configured
- **OpenTofu** or **Terraform** installed (only needed for this bootstrap step; the platform containers include OpenTofu)

### Create an Admin IAM User

1. Go to AWS Console → IAM → Users → Create user
2. Enter a username (e.g., `caution-admin`)
3. Click Next, then select "Attach policies directly"
4. Search for and select `AdministratorAccess`
5. Click Next, then Create user
6. Select the user → Security credentials → Create access key
7. Choose "Command Line Interface (CLI)", confirm, and **download the CSV file** (you'll need these credentials in the following steps)

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

## 1. Clone and configure

1. Clone the repository

   ```
   git clone https://codeberg.org/caution/platform.git
   cd platform/infra-bootstrap
   ```

2. Edit `variables.tf` to set a unique S3 bucket name:
   `nano variables.tf`
   Find the state_bucket_name variable and change the default value:

   ```
   variable "state_bucket_name" {
   default = "mycompany-caution-terraform-state" # Change this to something unique
   }
   ```

   Save with Ctrl+O, exit with Ctrl+X.

### Available variables for customization

Edit `variables.tf` to customize (or override via `-var` flags):

| Variable            | Default                     | Required to change?                   | Description                                                      |
| ------------------- | --------------------------- | ------------------------------------- | ---------------------------------------------------------------- |
| `state_bucket_name` | `caution-terraform-state`   | **Yes**                               | S3 bucket for Terraform state — must be globally unique          |
| `eif_bucket_name`   | `caution-eif-storage`       | **Yes**                               | S3 bucket for enclave images — must be globally unique           |
| `aws_region`        | `us-west-2`                 | Only if you prefer a different region | AWS region for all resources                                     |
| `lock_table_name`   | `terraform-state-lock`      | No                                    | DynamoDB table name                                              |
| `service_user_name` | `caution-terraform-service` | No                                    | IAM user name                                                    |

**Important:** S3 bucket names must be globally unique across all AWS accounts. Change `state_bucket_name` to something unique like `mycompany-caution-terraform-state`.

## 2. Disable backend (first-time only)

Before running the bootstrap, temporarily disable the backend configuration:

```
mv backend.tf backend.tf.disabled
```

This file references an S3 bucket that doesn't exist yet. You'll restore it after the bootstrap creates the bucket.

## 3. Run the bootstrap

### Option 1: Direct execution (recommended for first-time setup)

Make sure you're in the `infra-bootstrap` directory, then run the bootstrap script:

```
./entrypoint.sh
```

The script will:

1. Check for AWS CLI and Terraform/OpenTofu
2. Verify AWS credentials
3. Initialize Terraform
4. Show the plan and ask for confirmation
5. Apply the configuration
6. Output and save the new IAM credentials

### Option 2: Container execution

```bash
cd infra-bootstrap

# Set AWS credentials
export AWS_ACCESS_KEY_ID=your-admin-key
export AWS_SECRET_ACCESS_KEY=your-admin-secret

# Run via container
./run.sh apply
```

Or if you have `~/.aws` configured, the script will mount that automatically.

## 4. Migrate state to S3

1. Restore the backend configuration:

   ```bash
   mv backend.tf.disabled backend.tf
   ```

2. Update `backend.tf` to match your bucket name:

   ```bash
   nano backend.tf
   ```

   Change the `bucket` value to the same name you set in `variables.tf`, then save.

3. Migrate the local state to S3:

   ```bash
   tofu init -migrate-state
   # or: terraform init -migrate-state
   ```

## 5. Configure the platform

Go back to the root of the project and set up the `.env` file using the credentials from the bootstrap output:

```bash
cd ..
cp env.example .env
# Edit .env with your AWS credentials and bucket names
```

You're now ready to run the platform! Return to the [main README](../README.md#run-the-platform) to continue.

## Reference

### Outputs

After successful execution:

1. **Console output** displays the new IAM credentials
2. **`outputs.json`** contains all outputs in JSON format
3. **`../aws-credentials.env`** contains credentials in shell-sourceable format:

   ```bash
   AWS_ACCESS_KEY_ID=...
   AWS_SECRET_ACCESS_KEY=...
   AWS_REGION=us-west-2
   TERRAFORM_STATE_BUCKET=<YOUR_STATE_BUCKET_NAME>
   EIF_S3_BUCKET=<YOUR_EIF_BUCKET_NAME>
   ```

### Created IAM Permissions

The service IAM user has these permissions:

- **S3**: Read/write to the Terraform state bucket and EIF storage bucket
- **DynamoDB**: Read/write to the state lock table
- **EC2**: Create and manage instances for enclave deployments
- **IAM**: Limited permissions for instance profiles

### Destroy the bootstrap

To tear down the bootstrap infrastructure:

```bash
tofu destroy
# or: terraform destroy
```

**Warning:** This will delete the S3 bucket (including all Terraform state!) and the DynamoDB table. Only do this if you're completely removing the Caution installation.

### Troubleshooting

**"Bucket name already exists"**

S3 bucket names are globally unique. Change `state_bucket_name` in `variables.tf` to something unique.

**"Access Denied" errors**

Ensure you're using root or admin credentials with full AWS access. The bootstrap creates resources that require elevated permissions.

**Backend initialization fails**

If you see errors about the S3 backend not existing, you're hitting the chicken-and-egg problem. See step 2 above.
