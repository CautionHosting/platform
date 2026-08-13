# Bootstrap AWS Infrastructure

This guide walks you through setting up the required AWS infrastructure for the Caution platform in a target AWS account. It creates:

- **S3 bucket** for Terraform state storage (versioned, encrypted)
- **S3 bucket** for storing enclave images (EIFs)
- **DynamoDB table** for Terraform state locking
- **IAM user** with scoped permissions for the Caution platform service
- **Protected Route53 public hosted zone** for `apps.caution.sh`, with a 60-second SOA TTL

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
| `apps_dns_zone_name` | `apps.caution.sh`        | Optional         | Delegated suffix for managed application records |
| `lock_table_name`   | `terraform-state-lock`   | No               | DynamoDB table name                              |
| `service_user_name` | `caution-platform`       | No               | IAM user name                                    |
| `create_platform_access_key` | `false`             | Optional         | Create a new long-lived service key in Terraform state; enable only for first-time bootstrap |

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

### Dedicated builder network options

By default, bootstrap looks for the default VPC and uses the first public subnet in it for dedicated builders.

For production, you can point the builder resources at an existing subnet instead:

```bash
terraform apply \
  -var="state_bucket_name=caution-terraform-state-123456789012" \
  -var="eif_bucket_name=caution-eif-storage-123456789012" \
  -var="builder_subnet_id=subnet-0123456789abcdef0"
```

Bootstrap will derive the subnet's VPC automatically. You can also pass `builder_vpc_id` if you want the configuration to state that choice explicitly.

From the repository root, `make setup-builder` accepts the same values via environment variables:

```bash
BUILDER_SUBNET_ID=subnet-0123456789abcdef0 \
make setup-builder
```

The builder subnet should already have the outbound connectivity your builders need, typically via a NAT gateway or equivalent internet egress path.

## 3. Configure the platform

Go back to the root of the project and set up the `.env` file using the credentials from the bootstrap output:

```bash
cd ..
cp env.example .env
```

Set these values in `.env`. By default bootstrap does not create or rotate a
platform access key; continue using the operationally managed credentials
already deployed to the service. For a first-time installation only, pass
`-var="create_platform_access_key=true"` and securely capture the sensitive
outputs:
```
AWS_ACCESS_KEY_ID=<from terraform output>
AWS_SECRET_ACCESS_KEY=<from terraform output>
AWS_ACCOUNT_ID=<target account id>
TERRAFORM_STATE_BUCKET=<your state bucket name>
EIF_S3_BUCKET=<your eif bucket name>
CAUTION_APPS_DNS_ZONE_ID=<from apps_dns_zone_id output>
CAUTION_APPS_DNS_SUFFIX=<apps_dns_zone_name; defaults to apps.caution.sh>
```

For an isolated development zone, pass the suffix to bootstrap and use the
same value in the API environment, for example:

```bash
terraform apply -var="apps_dns_zone_name=apps.aposdw.space" # plus the existing required variables
```

Before starting the production API, delegate `apps.caution.sh` from the current
`caution.sh` DNS provider. Add the four values from
`terraform output apps_dns_name_servers` as NS records for host `apps`. Do not
change the domain-level nameservers and do not migrate the parent zone.

Verify the delegation and the negative-cache setting publicly:

```bash
dig NS apps.caution.sh
dig SOA apps.caution.sh
```

The SOA record TTL must be 60 seconds. Then set `CAUTION_APPS_DNS_ZONE_ID` and
restart the API. Production startup fails if this variable is missing;
non-production runs with managed DNS disabled when it is unset.

The API reconciles interrupted app teardown independently from Route53
publication, including when managed DNS is disabled. Teardown concurrency is
limited to two operations per API process and may use up to two dedicated
PostgreSQL sessions so long OpenTofu operations do not occupy the API pool.
The dedicated OpenTofu session locks use a separate advisory-lock namespace
from the short Route53 transactions. Failed deploy rollback is also recorded as
`terminating`; the same worker completes its DNS-safe cleanup and restores the
app to the redeployable `failed` state after an API restart.

If an unsuspend health or attestation check fails after recovering a different
Elastic IP, the API stops the instances it just started and leaves managed DNS
unchanged. If that compensating stop also fails, the API records the app as
running and metered with a DNS retry error but does not publish the unready IP.
Fix readiness, suspend the app, and retry unsuspend; the next successful
readiness check publishes the recovered IP.

### Production rollout checklist

1. Have an AWS administrator review and apply this existing `infra-bootstrap`
   state. This creates the zone and updates the existing platform IAM policy.
2. Have the parent-DNS administrator add the four `apps` NS values at the
   current `caution.sh` provider.
3. Verify the public NS and SOA answers, including the 60-second SOA TTL.
4. Set `CAUTION_APPS_DNS_ZONE_ID` and deploy or restart the API.
5. Run one real deploy, customer CNAME, TLS, and destroy smoke test.

Existing customers must replace a direct A record with the returned CNAME and
wait the former A record's TTL once. This is a customer-DNS migration, not a
per-app AWS administrator action. The customer CNAME is not an HTTP redirect
and remains owned by the customer's DNS provider; the platform neither creates
nor deletes it. Caution manages only the `<app-id>.apps.caution.sh` A record.
A normal successful app destruction withdraws that managed record, waits for
Route53 `INSYNC` and the 60-second TTL drain, then releases the Elastic IP. A DNS
withdrawal failure retains the IP and blocks teardown. A later provider-teardown
failure is retryable unless a force destroy marks the app destroyed, in which
case operators must reconcile possible provider leftovers. Redeploying the same
app ID can receive a new IP while retaining the same managed hostname, so the
customer CNAME does not need to change. Permanent destruction leaves the
customer-owned CNAME dangling until the customer removes or repoints it.

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
- **Route53**: UPSERT/DELETE only A records under `*.apps.caution.sh`, list only
  that hosted zone's records, and inspect Route53 change status

These Route53 permissions belong only to the existing platform identity.
Customer and BYOC credentials receive no Route53 permission, and there is no
per-app AWS administrator step.

## Destroy

To tear down the bootstrap infrastructure:

```bash
terraform destroy \
  -var="state_bucket_name=caution-terraform-state-123456789012" \
  -var="eif_bucket_name=caution-eif-storage-123456789012"
```

**Warning:** This will delete the S3 buckets (including all Terraform state!) and the DynamoDB table. The `apps.caution.sh` zone and its SOA record are protected with `prevent_destroy`; remove that protection only as a deliberate separate DNS-retirement change.

## Troubleshooting

**"Bucket name already exists"**

S3 bucket names are globally unique. Use account-ID-suffixed names like `caution-terraform-state-123456789012`.

**"Access Denied" errors**

Ensure you're using admin credentials with full AWS access for the target account. The bootstrap creates IAM users and policies that require elevated permissions.
