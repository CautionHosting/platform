#!/bin/bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

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
$TF_CMD plan -out=tfplan

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
$TF_CMD output -json > outputs.json
echo -e "${GREEN}OK${NC} Saved to outputs.json"

echo ""
echo -e "${GREEN}Bootstrap complete!${NC}"
echo ""
echo "=========================================="
echo "Platform Credentials (store securely!):"
echo "=========================================="
echo ""
echo "AWS_ACCESS_KEY_ID=$($TF_CMD output -raw aws_access_key_id)"
echo "AWS_SECRET_ACCESS_KEY=$($TF_CMD output -raw aws_secret_access_key)"
echo "AWS_ACCOUNT_ID=$ACCOUNT_ID"
echo "AWS_REGION=us-west-2"
echo "TERRAFORM_STATE_BUCKET=$($TF_CMD output -raw s3_bucket_name)"
echo "EIF_S3_BUCKET=$($TF_CMD output -raw eif_bucket_name)"
echo ""
echo "=========================================="
echo ""

CREDS_FILE="../aws-credentials.env"
cat > $CREDS_FILE << EOF
AWS_ACCESS_KEY_ID=$($TF_CMD output -raw aws_access_key_id)
AWS_SECRET_ACCESS_KEY=$($TF_CMD output -raw aws_secret_access_key)
AWS_ACCOUNT_ID=$ACCOUNT_ID
AWS_REGION=us-west-2
TERRAFORM_STATE_BUCKET=$($TF_CMD output -raw s3_bucket_name)
EIF_S3_BUCKET=$($TF_CMD output -raw eif_bucket_name)
EOF

chmod 600 $CREDS_FILE

echo -e "${GREEN}OK${NC} Credentials saved to: $CREDS_FILE"
echo -e "${YELLOW}WARNING${NC} Keep this file secure! Add it to .gitignore"
echo ""

echo -e "${YELLOW}Testing the setup...${NC}"
source $CREDS_FILE

if aws s3 ls s3://$TERRAFORM_STATE_BUCKET/ &> /dev/null; then
    echo -e "${GREEN}OK${NC} S3 state bucket access: OK"
else
    echo -e "${RED}FAIL${NC} S3 state bucket access: FAILED"
fi

if aws s3 ls s3://$EIF_S3_BUCKET/ &> /dev/null; then
    echo -e "${GREEN}OK${NC} S3 EIF bucket access: OK"
else
    echo -e "${RED}FAIL${NC} S3 EIF bucket access: FAILED"
fi

echo ""
echo -e "${GREEN}Bootstrap complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Copy credentials to your platform .env file"
echo "  2. Run 'make up' to start the platform"
echo ""
echo "To use these credentials in your shell:"
echo "  source $CREDS_FILE"
