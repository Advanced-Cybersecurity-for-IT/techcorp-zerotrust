#!/bin/bash
# ============================================================================
# Keycloak User Initialization Script
# Sets passwords for all users after Keycloak starts
# ============================================================================

set -e

KEYCLOAK_URL="${KEYCLOAK_URL:-http://keycloak:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-TechCorp2024!}"
REALM="techcorp"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ============================================================================
# User credentials to set
# ============================================================================
declare -A USERS
USERS["m.rossi"]="Ceo2024!"
USERS["l.bianchi"]="Cto2024!"
USERS["g.ferrari"]="Hr2024!"
USERS["a.romano"]="Sales2024!"
USERS["f.colombo"]="Dev2024!"
USERS["s.ricci"]="Analyst2024!"

# ============================================================================
# Wait for Keycloak to be ready
# ============================================================================
wait_for_keycloak() {
    log_info "Waiting for Keycloak to be ready at ${KEYCLOAK_URL}..."

    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        # Check if the master realm endpoint responds (reliable indicator)
        if curl -s -f "${KEYCLOAK_URL}/realms/master" > /dev/null 2>&1; then
            log_info "Keycloak is ready!"
            return 0
        fi

        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    log_error "Keycloak did not become ready in time"
    return 1
}

# ============================================================================
# Get admin access token
# ============================================================================
get_admin_token() {
    log_info "Getting admin access token..."

    local response
    response=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=admin-cli" \
        -d "username=${ADMIN_USER}" \
        -d "password=${ADMIN_PASSWORD}" \
        -d "grant_type=password")

    ADMIN_TOKEN=$(echo "$response" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

    if [ -z "$ADMIN_TOKEN" ]; then
        log_error "Failed to get admin token"
        echo "$response"
        return 1
    fi

    log_info "Admin token obtained successfully"
    return 0
}

# ============================================================================
# Get user ID by username
# ============================================================================
get_user_id() {
    local username="$1"

    local response
    response=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users?username=${username}&exact=true" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}")

    # Extract user ID from response
    local user_id
    user_id=$(echo "$response" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)

    echo "$user_id"
}

# ============================================================================
# Set user password
# ============================================================================
set_user_password() {
    local user_id="$1"
    local password="$2"

    local response
    response=$(curl -s -w "\n%{http_code}" -X PUT "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}/reset-password" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"type\":\"password\",\"value\":\"${password}\",\"temporary\":false}")

    local http_code
    http_code=$(echo "$response" | tail -1)

    if [ "$http_code" = "204" ]; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo "============================================"
    echo "Keycloak User Initialization"
    echo "============================================"
    echo ""

    # Wait for Keycloak
    wait_for_keycloak || exit 1

    # Small additional delay to ensure realm is fully loaded
    sleep 5

    # Get admin token
    get_admin_token || exit 1

    echo ""
    log_info "Setting user passwords in realm '${REALM}'..."
    echo ""

    local success_count=0
    local fail_count=0

    for username in "${!USERS[@]}"; do
        password="${USERS[$username]}"

        # Get user ID
        user_id=$(get_user_id "$username")

        if [ -z "$user_id" ]; then
            log_warn "User '$username' not found, skipping"
            fail_count=$((fail_count + 1))
            continue
        fi

        # Set password
        if set_user_password "$user_id" "$password"; then
            log_info "Password set for user: $username"
            success_count=$((success_count + 1))
        else
            log_error "Failed to set password for user: $username"
            fail_count=$((fail_count + 1))
        fi
    done

    echo ""
    echo "============================================"
    log_info "Initialization complete!"
    log_info "Success: $success_count, Failed: $fail_count"
    echo "============================================"

    if [ $fail_count -gt 0 ]; then
        exit 1
    fi

    exit 0
}

main "$@"
