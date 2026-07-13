#!/bin/bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../.env" ]]; then
    source "$SCRIPT_DIR/../.env"
fi

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-caution}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"

export PGPASSWORD="$DB_PASSWORD"

SHA_REGEX='^[0-9a-fA-F]{7,40}$'
DATE_REGEX='^[0-9]{4}-[0-9]{2}-[0-9]{2}$'

usage() {
    cat <<EOF
Create a new inactive legal_documents row from a caution/website commit.

Usage:
  ./utils/add-legal-doc-from-website.sh \\
    --website-repo /path/to/caution/website \\
    --document-type terms_of_service|privacy_notice|<any-type> \\
    --source-path terms.md|privacy.md \\
    --commit <sha> \\
    --version <display-version> \\
    --url <public-url> \\
    --effective-at YYYY-MM-DD [options]

Options:
  --title <text>           Display title (defaults to a humanized document_type, e.g.
                            "dpa" -> "Dpa", if omitted)
  --blocking true|false    requires_blocking_reacceptance (required for unknown types;
                            defaulted for terms_of_service/privacy_notice below)
  --ack true|false         requires_acknowledgment (required for unknown types; defaulted
                            for terms_of_service/privacy_notice below)
  --summary-json <json>    Optional summary_json payload
  --activate               Activate immediately after insert
  --help                   Show this message

document_type is not restricted to a fixed list — any string works. Known-type defaults:
  terms_of_service => blocking=true, ack=false
  privacy_notice   => blocking=false, ack=true
Any other document_type requires --blocking and --ack to be passed explicitly.

Requires local commands: git, psql, sed, awk, and a SHA-256 tool.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

psql_cmd() {
    psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -A "$@"
}

sql_quote() {
    printf "%s" "$1" | sed "s/'/''/g"
}

hash_stdin() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -r | awk '{print $1}'
    else
        die "No SHA-256 tool found (need sha256sum, shasum, or openssl)"
    fi
}

validate_bool() {
    case "$1" in
        true|false) ;;
        *) die "Expected boolean true|false, got: $1" ;;
    esac
}

validate_regex() {
    local value="$1"
    local regex="$2"
    local message="$3"
    if ! [[ "$value" =~ $regex ]]; then
        die "$message"
    fi
}

WEBSITE_REPO=""
DOCUMENT_TYPE=""
SOURCE_PATH=""
COMMIT_SHA=""
VERSION=""
URL=""
EFFECTIVE_AT=""
TITLE=""
BLOCKING=""
ACK=""
SUMMARY_JSON=""
ACTIVATE="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --website-repo)
            WEBSITE_REPO="${2:-}"
            shift 2
            ;;
        --document-type)
            DOCUMENT_TYPE="${2:-}"
            shift 2
            ;;
        --source-path)
            SOURCE_PATH="${2:-}"
            shift 2
            ;;
        --commit)
            COMMIT_SHA="${2:-}"
            shift 2
            ;;
        --version)
            VERSION="${2:-}"
            shift 2
            ;;
        --url)
            URL="${2:-}"
            shift 2
            ;;
        --effective-at)
            EFFECTIVE_AT="${2:-}"
            shift 2
            ;;
        --title)
            TITLE="${2:-}"
            shift 2
            ;;
        --blocking)
            BLOCKING="${2:-}"
            shift 2
            ;;
        --ack)
            ACK="${2:-}"
            shift 2
            ;;
        --summary-json)
            SUMMARY_JSON="${2:-}"
            shift 2
            ;;
        --activate)
            ACTIVATE="true"
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
done

require_command git
require_command psql
require_command sed
require_command awk

[[ -n "$WEBSITE_REPO" ]] || die "--website-repo is required"
[[ -n "$DOCUMENT_TYPE" ]] || die "--document-type is required"
[[ -n "$SOURCE_PATH" ]] || die "--source-path is required"
[[ -n "$COMMIT_SHA" ]] || die "--commit is required"
[[ -n "$VERSION" ]] || die "--version is required"
[[ -n "$URL" ]] || die "--url is required"
[[ -n "$EFFECTIVE_AT" ]] || die "--effective-at is required"

[[ -d "$WEBSITE_REPO/.git" ]] || die "Not a git repo: $WEBSITE_REPO"
validate_regex "$COMMIT_SHA" "$SHA_REGEX" "--commit must look like a git SHA"
validate_regex "$EFFECTIVE_AT" "$DATE_REGEX" "--effective-at must be YYYY-MM-DD"

case "$DOCUMENT_TYPE" in
    terms_of_service)
        : "${BLOCKING:=true}"
        : "${ACK:=false}"
        ;;
    privacy_notice)
        : "${BLOCKING:=false}"
        : "${ACK:=true}"
        ;;
    *)
        [[ -n "$BLOCKING" ]] || die "--blocking is required for document-type '$DOCUMENT_TYPE' (no default for unknown types)"
        [[ -n "$ACK" ]] || die "--ack is required for document-type '$DOCUMENT_TYPE' (no default for unknown types)"
        ;;
esac

validate_bool "$BLOCKING"
validate_bool "$ACK"

if ! git -C "$WEBSITE_REPO" rev-parse --verify "${COMMIT_SHA}^{commit}" >/dev/null 2>&1; then
    die "Commit not found in website repo: $COMMIT_SHA"
fi

if ! git -C "$WEBSITE_REPO" cat-file -e "${COMMIT_SHA}:${SOURCE_PATH}" 2>/dev/null; then
    die "File not found at commit: ${COMMIT_SHA}:${SOURCE_PATH}"
fi

CONTENT_SHA256="$(git -C "$WEBSITE_REPO" show "${COMMIT_SHA}:${SOURCE_PATH}" | hash_stdin)"

EXISTING_ID="$(psql_cmd -c "
    SELECT id
    FROM legal_documents
    WHERE document_type = '$(sql_quote "$DOCUMENT_TYPE")'
      AND content_sha256 = '$(sql_quote "$CONTENT_SHA256")'
    LIMIT 1;
")"

if [[ -n "$EXISTING_ID" ]]; then
    die "A ${DOCUMENT_TYPE} row with content_sha256=${CONTENT_SHA256} already exists (id=${EXISTING_ID})"
fi

SUMMARY_SQL="NULL"
if [[ -n "$SUMMARY_JSON" ]]; then
    SUMMARY_SQL="'$(sql_quote "$SUMMARY_JSON")'::jsonb"
fi

TITLE_SQL="NULL"
if [[ -n "$TITLE" ]]; then
    TITLE_SQL="'$(sql_quote "$TITLE")'"
fi

INSERTED_ID="$(psql_cmd -c "
    INSERT INTO legal_documents (
        document_type,
        title,
        version,
        url,
        effective_at,
        is_active,
        requires_blocking_reacceptance,
        requires_acknowledgment,
        source_path,
        source_commit_sha,
        content_sha256,
        summary_json
    ) VALUES (
        '$(sql_quote "$DOCUMENT_TYPE")',
        $TITLE_SQL,
        '$(sql_quote "$VERSION")',
        '$(sql_quote "$URL")',
        '$(sql_quote "$EFFECTIVE_AT")',
        false,
        $BLOCKING,
        $ACK,
        '$(sql_quote "$SOURCE_PATH")',
        '$(sql_quote "$COMMIT_SHA")',
        '$(sql_quote "$CONTENT_SHA256")',
        $SUMMARY_SQL
    )
    RETURNING id;
" | awk 'NF {print $1; exit}')"

if ! [[ "$INSERTED_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    die "Failed to capture inserted document id (got: '$INSERTED_ID')"
fi

if [[ "$ACTIVATE" == "true" ]]; then
    psql_cmd -c "
        BEGIN;
        UPDATE legal_documents
        SET is_active = false
        WHERE document_type = '$(sql_quote "$DOCUMENT_TYPE")'
          AND is_active = true;

        UPDATE legal_documents
        SET is_active = true
        WHERE id = '$(sql_quote "$INSERTED_ID")';
        COMMIT;
    " >/dev/null
fi

echo "Inserted legal document:"
echo "  id:              $INSERTED_ID"
echo "  document_type:   $DOCUMENT_TYPE"
echo "  version:         $VERSION"
echo "  effective_at:    $EFFECTIVE_AT"
echo "  source_path:     $SOURCE_PATH"
echo "  source_commit:   $COMMIT_SHA"
echo "  content_sha256:  $CONTENT_SHA256"
echo "  is_active:       $ACTIVATE"
