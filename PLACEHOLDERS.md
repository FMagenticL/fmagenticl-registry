# FMagenticL — Placeholder Ledger

Every value below must be replaced before the corresponding feature can be activated. Nothing here blocks the read path.

| # | Placeholder | File | Value Needed | User Step | Blocking |
|---|---|---|---|---|---|
| 1 | PLACEHOLDER_EDGE_CDN_URL | fmagenticl/client/config.py | Cloudflare Pages production URL | Create Pages project | Read path |
| 2 | PLACEHOLDER_EDGE_CDN_URL | dist/.well-known/mcp.json | Same as #1 | Same as #1 | Discovery |
| 3 | PLACEHOLDER_EDGE_CDN_URL | dist/.well-known/agent-card.json | Same as #1 | Same as #1 | Discovery |
| 4 | PLACEHOLDER_WORKER_URL | dist/.well-known/agent-card.json | Cloudflare Worker URL | Deploy Worker | Write path |
| 5 | PLACEHOLDER_D1_DATABASE_ID | serverless/wrangler.toml | Cloudflare D1 database ID | wrangler d1 create | Write path |
| 6 | PLACEHOLDER_SIGNING_KEY_NOT_SET | scripts/build_distribution.py | Ed25519 private key | Generate keypair | Optional |
| 7 | secrets.FMAGENTICL_SIGNING_KEY | .github/workflows/deploy.yml | GitHub Actions secret | Add to repo | CI |
| 8 | secrets.CLOUDFLARE_API_TOKEN | .github/workflows/deploy.yml | GitHub Actions secret | Add to repo | CI |
| 9 | secrets.CLOUDFLARE_ACCOUNT_ID | .github/workflows/deploy.yml | GitHub Actions secret | Add to repo | CI |

**None of the above blocks the read path.** The 47 static patches in `patches/` and the compiled distribution in `dist/v1/resolve/` are complete and can be served from any static host immediately.
