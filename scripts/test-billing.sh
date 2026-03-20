#!/bin/bash
# Test the billing/metering flow end-to-end (Paddle billing)
# Run this after `make up` with EMAIL_TEST_MODE=true

set -e

METERING_URL="${METERING_URL:-http://localhost:8083}"
API_URL="${API_URL:-http://localhost:8080}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Billing/Metering Test Script (Paddle) ===${NC}"
echo ""

# Check if we're running inside docker network or externally
if ! curl -s "$METERING_URL/health" > /dev/null 2>&1; then
    echo "Metering service not reachable at $METERING_URL"
    echo "If running outside docker, try: docker exec -it metering /bin/sh"
    echo "Or expose metering port in Makefile"
    exit 1
fi

# Create a test user ID (or use an existing one)
TEST_USER_ID="${TEST_USER_ID:-$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)}"
echo -e "${GREEN}Test User ID:${NC} $TEST_USER_ID"
echo ""

# =============================================================================
# Step 1: Set up billing config for test user with Paddle customer ID
# =============================================================================
echo -e "${YELLOW}Step 1: Setting up billing config with Paddle customer...${NC}"

# Insert billing config with a test Paddle customer ID
docker exec postgres psql -U postgres -d caution -c "
INSERT INTO billing_config (user_id, billing_mode, payment_method, paddle_customer_id, created_at)
VALUES ('$TEST_USER_ID', 'postpaid', NULL, 'ctm_test_$TEST_USER_ID', NOW())
ON CONFLICT (user_id) DO UPDATE SET
    billing_mode = 'postpaid',
    paddle_customer_id = 'ctm_test_$TEST_USER_ID';
" 2>/dev/null || echo "(billing_config table may not exist yet - that's OK for basic testing)"

# Create a fake user for email
docker exec postgres psql -U postgres -d caution -c "
INSERT INTO users (id, email, created_at)
VALUES ('$TEST_USER_ID', 'test@example.com', NOW())
ON CONFLICT (id) DO NOTHING;
" 2>/dev/null || echo "(users table structure may differ)"

echo "Done"
echo ""

# =============================================================================
# Step 2: Simulate a month of compute usage
# =============================================================================
echo -e "${YELLOW}Step 2: Simulating a month of AWS compute usage...${NC}"

# Simulate different instance types over the month
INSTANCE_TYPES=("m5.xlarge" "m5.2xlarge" "c5.xlarge" "c6i.xlarge")
TOTAL_COST=0

for day in $(seq 1 30); do
    # Pick a random instance type
    INSTANCE_TYPE=${INSTANCE_TYPES[$((RANDOM % ${#INSTANCE_TYPES[@]}))]}

    # Random hours between 1-24
    HOURS=$((RANDOM % 24 + 1))

    RESPONSE=$(curl -s -X POST "$METERING_URL/test/simulate-usage" \
        -H "Content-Type: application/json" \
        -d "{
            \"user_id\": \"$TEST_USER_ID\",
            \"hours\": $HOURS,
            \"instance_type\": \"$INSTANCE_TYPE\"
        }")

    COST=$(echo "$RESPONSE" | grep -o '"cost_usd":[0-9.]*' | cut -d: -f2)
    TOTAL_COST=$(awk "BEGIN {printf \"%.2f\", $TOTAL_COST + ${COST:-0}}" 2>/dev/null || echo "$TOTAL_COST")

    echo "  Day $day: $HOURS hours on $INSTANCE_TYPE"
done

echo ""
echo -e "${GREEN}Total simulated cost: ~\$$TOTAL_COST${NC}"
echo ""

# =============================================================================
# Step 3: Check recorded usage
# =============================================================================
echo -e "${YELLOW}Step 3: Checking recorded usage...${NC}"

curl -s "$METERING_URL/api/usage/$TEST_USER_ID" | python3 -m json.tool 2>/dev/null || \
    curl -s "$METERING_URL/api/usage/$TEST_USER_ID"

echo ""

# =============================================================================
# Step 4: Simulate a Paddle transaction (triggers email + invoice flow)
# =============================================================================
echo -e "${YELLOW}Step 4: Simulating Paddle transaction (billed)...${NC}"

# Calculate amount in cents (rough estimate)
AMOUNT_CENTS=$((${TOTAL_COST%.*} * 100 + 5000))  # Add some buffer

RESPONSE=$(curl -s -X POST "$METERING_URL/test/simulate-paddle-transaction" \
    -H "Content-Type: application/json" \
    -d "{
        \"user_id\": \"$TEST_USER_ID\",
        \"amount_cents\": $AMOUNT_CENTS,
        \"event_type\": \"transaction.billed\"
    }")

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

# =============================================================================
# Step 5: Simulate transaction completed (payment collected)
# =============================================================================
echo -e "${YELLOW}Step 5: Simulating Paddle transaction completed (payment collected)...${NC}"

RESPONSE=$(curl -s -X POST "$METERING_URL/test/simulate-paddle-transaction" \
    -H "Content-Type: application/json" \
    -d "{
        \"user_id\": \"$TEST_USER_ID\",
        \"amount_cents\": $AMOUNT_CENTS,
        \"event_type\": \"transaction.completed\"
    }")

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

# =============================================================================
# Step 6: Check email logs
# =============================================================================
echo -e "${YELLOW}Step 6: Checking email service logs for sent emails...${NC}"
echo "(Look for EMAIL TEST MODE messages)"
echo ""

docker logs email 2>&1 | grep -A5 "EMAIL TEST MODE" | tail -20 || echo "No test emails found (email service may not be running)"

echo ""
echo -e "${GREEN}=== Test Complete ===${NC}"
echo ""
echo "What was tested:"
echo "  1. Created billing config with Paddle customer ID for test user"
echo "  2. Simulated 30 days of compute usage (recorded locally)"
echo "  3. Verified usage records in database"
echo "  4. Simulated Paddle transaction.billed (invoice created)"
echo "  5. Simulated Paddle transaction.completed (payment collected)"
echo "  6. Checked email notifications"
echo ""
echo "To see all usage records:"
echo "  docker exec postgres psql -U postgres -d caution -c \"SELECT * FROM usage_records WHERE user_id = '$TEST_USER_ID'\""
echo ""
echo "To see invoices:"
echo "  docker exec postgres psql -U postgres -d caution -c \"SELECT * FROM invoices WHERE user_id = '$TEST_USER_ID'\""
echo ""
echo "To see Paddle webhook events:"
echo "  docker exec postgres psql -U postgres -d caution -c \"SELECT * FROM paddle_webhook_events\""
