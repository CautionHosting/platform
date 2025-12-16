#!/bin/bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

IMAGE_NAME="infra-bootstrap"

echo "🐳 Infrastructure Bootstrap Container Runner"
echo "============================================="
echo ""

if ! docker images | grep -q "^${IMAGE_NAME} "; then
    echo "📦 Building container image..."
    docker build -t $IMAGE_NAME -f Containerfile .
    echo ""
fi

AWS_CREDS_ARGS=""

if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "✓ Using AWS credentials from environment"
    AWS_CREDS_ARGS="-e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"
    if [ -n "$AWS_SESSION_TOKEN" ]; then
        AWS_CREDS_ARGS="$AWS_CREDS_ARGS -e AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN"
    fi
elif [ -d "$HOME/.aws" ]; then
    echo "✓ Using AWS credentials from ~/.aws"
    AWS_CREDS_ARGS="-v $HOME/.aws:/root/.aws:ro"
else
    echo "❌ No AWS credentials found!"
    echo ""
    echo "Provide credentials via:"
    echo "  export AWS_ACCESS_KEY_ID=..."
    echo "  export AWS_SECRET_ACCESS_KEY=..."
    echo "OR have AWS CLI configured in ~/.aws/"
    exit 1
fi

COMMAND="${1:-apply}"

echo ""
echo "Running: $COMMAND"
echo ""

docker run --rm -it \
    $AWS_CREDS_ARGS \
    -v "$(pwd):/workspace" \
    $IMAGE_NAME \
    $COMMAND

echo ""
echo "✅ Done!"
echo ""

if [ "$COMMAND" = "apply" ]; then
    if [ -f aws-credentials.env ]; then
        echo "📝 Credentials saved to: aws-credentials.env"
        echo ""
        echo "Next steps:"
        echo "  1. source aws-credentials.env"
        echo "  2. Add credentials to your API deployment"
        echo "  3. Deploy your application"
    fi
fi
