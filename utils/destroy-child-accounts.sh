#!/bin/bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

# close-all-child-accounts.sh - Close AWS child accounts (doesn't require removal)

set -e

S3_BUCKET="${TERRAFORM_STATE_BUCKET:-caution-terraform-state}"
AWS_REGION="${AWS_REGION:-us-west-2}"

echo "=========================================="
echo "CLOSE ALL AWS CHILD ACCOUNTS"
echo "=========================================="
echo ""

# Get org slugs from S3
echo "Fetching organizations from S3..."
ORG_SLUGS=$(aws s3 ls "s3://$S3_BUCKET/organizations/" --recursive | \
    grep terraform.tfstate | \
    awk '{print $4}' | \
    sed 's|^organizations/||' | \
    sed 's|/terraform.tfstate$||')

if [ -z "$ORG_SLUGS" ]; then
    echo "No organizations found"
    exit 0
fi

TOTAL_COUNT=$(echo "$ORG_SLUGS" | wc -l)
echo "Found $TOTAL_COUNT organizations"
echo ""

# Get account IDs from state files
declare -A ORG_TO_ACCOUNT
for slug in $ORG_SLUGS; do
    echo "Processing $slug..."
    STATE_FILE=$(mktemp)
    aws s3 cp "s3://$S3_BUCKET/organizations/$slug/terraform.tfstate" "$STATE_FILE" 2>/dev/null || {
        echo "  ⚠ Could not download state file"
        continue
    }
    
    # Extract account ID from state
    ACCOUNT_ID=$(cat "$STATE_FILE" | jq -r '.resources[] | select(.type == "aws_organizations_account") | .instances[0].attributes.id' 2>/dev/null)
    
    if [ -n "$ACCOUNT_ID" ] && [ "$ACCOUNT_ID" != "null" ]; then
        ORG_TO_ACCOUNT[$slug]=$ACCOUNT_ID
        echo "  Org: $slug"
        echo "  AWS Account: $ACCOUNT_ID"
    else
        echo "  ⚠ Could not find account ID in state"
    fi
    
    rm -f "$STATE_FILE"
    echo ""
done

if [ ${#ORG_TO_ACCOUNT[@]} -eq 0 ]; then
    echo "No accounts found to close"
    exit 0
fi

echo "=========================================="
echo "Accounts to close:"
for slug in "${!ORG_TO_ACCOUNT[@]}"; do
    echo "  - $slug (AWS Account: ${ORG_TO_ACCOUNT[$slug]})"
done
echo ""
echo "WARNING: This will CLOSE ${#ORG_TO_ACCOUNT[@]} AWS accounts!"
echo "Closed accounts will be suspended immediately and deleted after 90 days."
echo "=========================================="
echo ""
read -p "Type 'close-all-accounts' to confirm: " confirm

if [ "$confirm" != "close-all-accounts" ]; then
    echo "Aborted"
    exit 0
fi

echo ""
echo "Closing accounts..."
echo ""

SUCCESS_COUNT=0
FAIL_COUNT=0
FAILED_ACCOUNTS=()

for slug in "${!ORG_TO_ACCOUNT[@]}"; do
    ACCOUNT_ID=${ORG_TO_ACCOUNT[$slug]}
    echo "Closing account: $ACCOUNT_ID ($slug)..."
    
    if aws organizations close-account --account-id "$ACCOUNT_ID" 2>&1; then
        echo "✓ Closed account $ACCOUNT_ID"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        
        # Delete state file
        echo "  Cleaning up state file..."
        aws s3 rm "s3://$S3_BUCKET/organizations/$slug/terraform.tfstate" && echo "  ✓ State deleted"
    else
        echo "✗ Failed to close account $ACCOUNT_ID"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_ACCOUNTS+=("$slug ($ACCOUNT_ID)")
    fi
    echo ""
done

echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "Total: ${#ORG_TO_ACCOUNT[@]}"
echo "Success: $SUCCESS_COUNT"
echo "Failed: $FAIL_COUNT"
echo ""

if [ $FAIL_COUNT -gt 0 ]; then
    echo "Failed accounts:"
    for acc in "${FAILED_ACCOUNTS[@]}"; do
        echo "  - $acc"
    done
    echo ""
fi

if [ $SUCCESS_COUNT -gt 0 ]; then
    echo "✓ Successfully closed $SUCCESS_COUNT AWS child accounts"
    echo ""
    echo "Accounts are now suspended and will be deleted after 90 days."
    echo ""
    echo "Update database:"
    echo "  psql \$DATABASE_URL -c \"UPDATE provider_accounts SET is_active = false;\""
fi

if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi
