#!/bin/bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e
umask 077

COMMAND=apply
if [[ "${1:-}" == "plan" || "${1:-}" == "apply" ]]; then
    COMMAND="$1"
    shift
fi

PLAN_ARGS=()
while (( $# )); do
    case "$1" in
        -var|-var-file)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "A value is required after -var or -var-file." >&2
                exit 2
            fi
            PLAN_ARGS+=("$1" "$2")
            shift 2
            ;;
        -var=?*|-var-file=?*)
            PLAN_ARGS+=("$1")
            shift
            ;;
        *)
            echo "Usage: $0 [plan|apply] [-var NAME=VALUE] [-var-file FILE] ..." >&2
            exit 2
            ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Terraform Bootstrap Setup${NC}"
echo "================================"
echo ""

if ! command -v aws &> /dev/null; then
    echo -e "${RED}AWS CLI not found. Please install it first.${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${RED}jq not found. Please install it first.${NC}"
    exit 1
fi

if command -v tofu &> /dev/null; then
    TF_CMD="tofu"
elif command -v terraform &> /dev/null; then
    TF_CMD="terraform"
else
    echo -e "${RED}Neither OpenTofu nor Terraform found. Please install one.${NC}"
    exit 1
fi

echo -e "${GREEN}OK${NC} Using: $TF_CMD"

echo -e "${YELLOW}Checking AWS credentials...${NC}"
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}AWS credentials not configured or invalid.${NC}"
    echo "Please run: aws configure"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo -e "${GREEN}OK${NC} AWS Account: $ACCOUNT_ID"

echo ""
echo -e "${YELLOW}Initializing Terraform...${NC}"
$TF_CMD init

echo ""
echo -e "${YELLOW}Creating execution plan...${NC}"
if [[ -f tfplan ]]; then
    chmod 600 tfplan
fi
"$TF_CMD" plan -out=tfplan "${PLAN_ARGS[@]}"

if [[ "$COMMAND" == "plan" ]]; then
    exit 0
fi

echo ""
echo -e "${YELLOW}Applying Terraform configuration...${NC}"
read -p "Continue with apply? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

$TF_CMD apply tfplan

echo ""
echo -e "${YELLOW}Saving outputs...${NC}"
CREDS_FILE="aws-credentials.env"
OUTPUTS_TMP=""
CREDS_TMP=""
trap 'rm -f -- "$OUTPUTS_TMP" "$CREDS_TMP"' EXIT
OUTPUTS_TMP=$(mktemp .outputs.json.XXXXXX)
"$TF_CMD" output -json > "$OUTPUTS_TMP"

REGION=$("$TF_CMD" output -raw aws_region)
TERRAFORM_STATE_BUCKET=$("$TF_CMD" output -raw s3_bucket_name)
EIF_S3_BUCKET=$("$TF_CMD" output -raw eif_bucket_name)
APPS_DNS_ZONE_ID=$("$TF_CMD" output -raw apps_dns_zone_id)
APPS_DNS_ZONE_NAME=$("$TF_CMD" output -raw apps_dns_zone_name)
# Terraform omits null outputs when no new platform key was requested.
PLATFORM_ACCESS_KEY_ID=$(jq -r '.aws_access_key_id.value // empty' "$OUTPUTS_TMP")
if [[ -n "$PLATFORM_ACCESS_KEY_ID" ]]; then
    PLATFORM_ACCESS_KEY_ID=$("$TF_CMD" output -raw aws_access_key_id)
    PLATFORM_SECRET_ACCESS_KEY=$("$TF_CMD" output -raw aws_secret_access_key)
fi

CREDS_TMP=$(mktemp .aws-credentials.env.XXXXXX)
{
    printf 'AWS_ACCOUNT_ID=%q\n' "$ACCOUNT_ID"
    printf 'AWS_REGION=%q\n' "$REGION"
    printf 'TERRAFORM_STATE_BUCKET=%q\n' "$TERRAFORM_STATE_BUCKET"
    printf 'EIF_S3_BUCKET=%q\n' "$EIF_S3_BUCKET"
    printf 'CAUTION_APPS_DNS_ZONE_ID=%q\n' "$APPS_DNS_ZONE_ID"
    printf 'CAUTION_APPS_DNS_SUFFIX=%q\n' "$APPS_DNS_ZONE_NAME"
    if [[ -n "$PLATFORM_ACCESS_KEY_ID" ]]; then
        printf 'AWS_ACCESS_KEY_ID=%q\n' "$PLATFORM_ACCESS_KEY_ID"
        printf 'AWS_SECRET_ACCESS_KEY=%q\n' "$PLATFORM_SECRET_ACCESS_KEY"
    fi
} > "$CREDS_TMP"
mv -f -- "$OUTPUTS_TMP" outputs.json
mv -f -- "$CREDS_TMP" "$CREDS_FILE"

echo -e "${GREEN}OK${NC} Saved to outputs.json"

echo -e "${GREEN}OK${NC} Credentials saved to: $CREDS_FILE"
echo -e "${YELLOW}WARNING${NC} Keep this file secure! Add it to .gitignore"
echo ""

echo -e "${YELLOW}Checking bucket access with bootstrap credentials...${NC}"

if aws s3 ls "s3://$TERRAFORM_STATE_BUCKET/" &> /dev/null; then
    echo -e "${GREEN}OK${NC} S3 state bucket access: OK"
else
    echo -e "${RED}FAIL${NC} S3 state bucket access: FAILED"
fi

if aws s3 ls "s3://$EIF_S3_BUCKET/" &> /dev/null; then
    echo -e "${GREEN}OK${NC} S3 EIF bucket access: OK"
else
    echo -e "${RED}FAIL${NC} S3 EIF bucket access: FAILED"
fi

echo ""
echo -e "${GREEN}Bootstrap complete!${NC}"
echo ""
echo "Next steps:"
APPS_DNS_ZONE_NAME=$($TF_CMD output -raw apps_dns_zone_name)
echo "  1. At the parent DNS provider, delegate '$APPS_DNS_ZONE_NAME' to these Route53 nameservers:"
$TF_CMD output -json apps_dns_name_servers
echo "  2. Copy credentials, CAUTION_APPS_DNS_ZONE_ID, and CAUTION_APPS_DNS_SUFFIX=$APPS_DNS_ZONE_NAME to your platform .env file"
echo "  3. Verify public NS and SOA answers for $APPS_DNS_ZONE_NAME"
echo "  4. Run 'make up' to start the platform"
echo ""
echo "To use these credentials in your shell:"
echo "  source $CREDS_FILE"
