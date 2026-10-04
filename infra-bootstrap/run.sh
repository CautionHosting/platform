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

AWS_CREDS_ARGS=()

if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "✓ Using AWS credentials from environment"
    AWS_CREDS_ARGS+=(-e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY)
    if [ -n "$AWS_SESSION_TOKEN" ]; then
        AWS_CREDS_ARGS+=(-e AWS_SESSION_TOKEN)
    fi
fi

if [ -d "$HOME/.aws" ]; then
    echo "✓ Using AWS credentials from ~/.aws"
    AWS_CREDS_ARGS+=(-v "$HOME/.aws:/tmp/.aws:ro")
    if [[ -d "$HOME/.aws/login/cache" ]]; then
        AWS_CREDS_ARGS+=(-v "$HOME/.aws/login/cache:/tmp/.aws/login/cache:rw")
    fi
elif [ ${#AWS_CREDS_ARGS[@]} -eq 0 ]; then
    echo "❌ No AWS credentials found!"
    echo ""
    echo "Provide credentials via:"
    echo "  export AWS_ACCESS_KEY_ID=..."
    echo "  export AWS_SECRET_ACCESS_KEY=..."
    echo "OR have AWS CLI configured in ~/.aws/"
    exit 1
fi

for name in AWS_PROFILE AWS_DEFAULT_PROFILE AWS_REGION AWS_DEFAULT_REGION; do
    if [[ -n "${!name}" ]]; then
        AWS_CREDS_ARGS+=(-e "$name")
    fi
done

if [[ $# -eq 0 ]]; then
    set -- apply
fi
COMMAND="${1:-apply}"

echo ""
echo "Running: $COMMAND"
echo ""

docker run --rm -it \
    --user "$(id -u):$(id -g)" -e HOME=/tmp \
    "${AWS_CREDS_ARGS[@]}" \
    -v "$(pwd):/workspace" \
    "$IMAGE_NAME" \
    "$@"

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
