#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== IAM Identity Center Analyzer - Deployment Script ===${NC}"

# Check prerequisites
command -v sam >/dev/null 2>&1 || { echo -e "${RED}Error: AWS SAM CLI is required but not installed.${NC}" >&2; exit 1; }
command -v aws >/dev/null 2>&1 || { echo -e "${RED}Error: AWS CLI is required but not installed.${NC}" >&2; exit 1; }

# Get parameters
read -p "Stack name [iam-identity-analyzer]: " STACK_NAME
STACK_NAME=${STACK_NAME:-iam-identity-analyzer}

read -p "AWS Region [us-east-1]: " REGION
REGION=${REGION:-us-east-1}

read -p "Email address for notifications: " EMAIL
if [ -z "$EMAIL" ]; then
    echo -e "${RED}Error: Email address is required${NC}"
    exit 1
fi

read -p "Identity Store ID (d-xxxxxxxxxx): " IDENTITY_STORE_ID
if [ -z "$IDENTITY_STORE_ID" ]; then
    echo -e "${RED}Error: Identity Store ID is required${NC}"
    exit 1
fi

read -p "Identity Store Instance ARN: " INSTANCE_ARN
if [ -z "$INSTANCE_ARN" ]; then
    echo -e "${RED}Error: Instance ARN is required${NC}"
    exit 1
fi

read -p "Environment [prod]: " ENVIRONMENT
ENVIRONMENT=${ENVIRONMENT:-prod}

echo ""
echo -e "${YELLOW}Deploying with:${NC}"
echo "  Stack Name: $STACK_NAME"
echo "  Region: $REGION"
echo "  Email: $EMAIL"
echo "  Identity Store ID: $IDENTITY_STORE_ID"
echo "  Instance ARN: $INSTANCE_ARN"
echo "  Environment: $ENVIRONMENT"
echo ""

read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 0
fi

# Build
echo -e "${GREEN}Building...${NC}"
sam build

# Deploy
echo -e "${GREEN}Deploying...${NC}"
sam deploy \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --parameter-overrides \
        EmailAddress="$EMAIL" \
        IdentityStoreID="$IDENTITY_STORE_ID" \
        IdentityStoreInstanceArn="$INSTANCE_ARN" \
        Environment="$ENVIRONMENT" \
    --capabilities CAPABILITY_NAMED_IAM \
    --resolve-s3 \
    --no-confirm-changeset

echo ""
echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo -e "${YELLOW}Don't forget to confirm the SNS subscription in your email!${NC}"
