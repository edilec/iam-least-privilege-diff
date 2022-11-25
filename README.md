# iam-least-privilege-diff

Offline, read-only comparison of two exported AWS IAM **identity policy documents**. It reports syntactic changes to `Allow` actions, resources, and simple equality constraints. It never computes effective permissions.

## Run

Node.js 22 or newer; no package dependencies or network calls.

```sh
node bin/iam-least-privilege-diff.mjs --root examples/pass --before before.json --after after.json
node bin/iam-least-privilege-diff.mjs --root examples/fail --before before.json --after after.json
npm run check
```

The CLI emits one JSON report. Exit 0 means `pass`, 1 means `fail`, and 2 means `incomplete` or invalid CLI options. Invalid options produce no stdout. Input files are resolved by realpath within `--root`; escapes, unreadable files, malformed JSON, duplicate decoded keys (including escaped spellings), and invalid UTF-8 yield `incomplete`. No files are written.

## Accepted input

Each file is an exported envelope:

```json
{"schemaVersion":"1","complete":true,"policy":{"Version":"2012-10-17","Statement":[{"Sid":"Read","Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::example/*"],"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}}
```

`complete:true` attests that the exported **single document** is complete, not that all policy layers were supplied. Every statement needs a unique stable `Sid`. This bounded subset accepts `Allow`, `Action`, `Resource`, and optional `StringEquals` values as strings or string arrays. Statement and action/resource order does not matter. New selectors and removed equality constraints fail; removed selectors are informational. Added `*` or `?` wildcards are called out. Changed equality values, unsupported syntax, missing coverage, or duplicate IDs are `incomplete`, never pass. Findings use fixed messages and logical `@before`/`@after` pointers; raw action, resource, condition, or file names are not echoed.

## Limits and non-goals

Each file is at most 524,288 bytes; each policy at most 1,000 statements; each statement at most 1,000 actions, 1,000 resources, and 100 `StringEquals` keys/values; JSON depth at most 16; evaluation deadline 5,000 ms with an injectable monotonic clock. At N the boundary is accepted; N+1 yields `incomplete`. Output order is deterministic UTF-16 code-unit order. The tool does not evaluate groups, attached/inline combinations, permission boundaries, resource policies, service control policies, session policies, explicit-deny effects, principals, condition operators beyond `StringEquals`, policy variables, wildcard expansion, or live AWS state. Its `effectivePermissions` field is always `not-evaluated`; a pass only means no concerning change was found in this supported comparison.
