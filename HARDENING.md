<!-- markdownlint-disable -->

# Hardening Report: MercymeIlya--last-workflow-status/v0.3.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **MercymeIlya--last-workflow-status/v0.3.5** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple `${{ }}` expressions are directly interpolated inside `run:` shell command strings in the composite action. In the 'Get workflow id' step, `${{ github.api_url }}`, `${{ github.repository }}`, `${{ github.run_id }}`, and `${{ inputs.github_token }}` are embedded directly in the shell script (e.g., `API_URL="${{ github.api_url }}/repos/${{ github.repository }}/actions/runs/${{ github.run_id }}"`). In the 'Get previous build status' step, the same pattern recurs with `${{ github.api_url }}`, `${{ github.repository }}`, `${{ env.WORKFLOW_ID }}`, `${{ env.BRANCH_NAME }}`, and `${{ inputs.github_token }}`. These values are substituted by the Actions runner before the shell sees the script, allowing an attacker to inject arbitrary shell commands via a crafted `github.*` or `inputs.*` value. All such values must be passed via `env:` variables and then referenced as quoted shell variables (e.g., `"$VAR"`) — never interpolated directly with `${{ }}` inside a `run:` block.

Locations:

- `action.yml:31`
- `action.yml:47`

### github-env-injection (severity: high)

Two `run:` steps write values derived from untrusted/inherited sources to `$GITHUB_ENV` without the required sanitization (`printf '%s' "$VAR" | tr -d '\n\r'`). (1) 'Get branch name' step (line 21): `BRANCH_NAME` is set from `$GITHUB_HEAD_REF` — an inherited process env var equivalent to `github.head_ref`, which is attacker-controlled on pull requests — and written unsanitized to `$GITHUB_ENV` at line 27: `echo "BRANCH_NAME=${BRANCH_NAME}" >> $GITHUB_ENV`. A newline injected into `GITHUB_HEAD_REF` can define arbitrary additional environment variables for subsequent steps. (2) 'Get workflow id' step (line 31): `WORKFLOW_ID` is populated from an API response and written unsanitized to `$GITHUB_ENV` at line 42: `echo "WORKFLOW_ID=${WORKFLOW_ID}" >> $GITHUB_ENV`. Both writes must be preceded by sanitization, e.g., `safe=$(printf '%s' "$BRANCH_NAME" | tr -d '\n\r')` before `echo "BRANCH_NAME=$safe" >> $GITHUB_ENV`.

Locations:

- `action.yml:27`
- `action.yml:42`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.github_token }}" appears directly in run: block of step "Get workflow id"; move to env: map

Locations:

- `action.yml:37`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.github_token }}" appears directly in run: block of step "Get previous build status"; move to env: map

Locations:

- `action.yml:54`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all four findings in hardened/action/action.yml:
1. script-injection: Moved all ${{ github.api_url }}, ${{ github.repository }}, ${{ github.run_id }}, ${{ inputs.github_token }}, ${{ env.WORKFLOW_ID }}, and ${{ env.BRANCH_NAME }} expressions out of run: blocks into env: maps. Shell scripts now reference them as quoted shell variables (e.g., "${API_URL_BASE}").
2. github-env-injection (BRANCH_NAME, line 27): Added sanitization step `safe_branch=$(printf '%s' "${BRANCH_NAME}" | tr -d '\n\r')` before writing to $GITHUB_ENV.
3. github-env-injection (WORKFLOW_ID, line 42): Added sanitization step `safe_workflow_id=$(printf '%s' "${WORKFLOW_ID}" | tr -d '\n\r')` before writing to $GITHUB_ENV.
4. static-inline-injection: Both occurrences of ${{ inputs.github_token }} in the 'Get workflow id' and 'Get previous build status' steps moved to env: blocks as GITHUB_TOKEN_VAL.
Note: In 'Get previous build status', WORKFLOW_ID and BRANCH_NAME are consumed from the process environment (set via $GITHUB_ENV by prior steps), so they don't need to be in the env: block — they are already sanitized shell environment variables.

