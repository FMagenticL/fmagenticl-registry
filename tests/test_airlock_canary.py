import json
import os
import sys
import subprocess
import pytest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE = "node"


def test_airlock_dead_drop_isolation_and_rate_limiting():
    """Phase 11.0 Airlock Verification:
    1. External grievance submissions are routed to DEAD_LETTER_QUARANTINE and returned with MAINTAINER_TRIAGE_ONLY.
    2. Quarantined canary entries are NEVER returned by getUnifiedWorkarounds or fmagenticl_resolve.
    3. Reverse-DoS rate limit prevents consecutive NACK bombing from the same IP.
    """
    esm_test = r"""
    import * as mcpMod from './functions/mcp.js';

    async function run() {
      // Mock D1 Database
      const d1Store = {
        grievances: [],
        rate_limits: new Map(),
        patch_health: new Map(),
        visits: []
      };

      const mockDb = {
        prepare(sql) {
          return {
            bind(...args) {
              return {
                async first() {
                  if (sql.includes('FROM rate_limits')) {
                    const [sub, win] = args;
                    const key = `${sub}:${win}`;
                    const count = d1Store.rate_limits.get(key) || 0;
                    return count > 0 ? { count } : null;
                  }
                  if (sql.includes('FROM patch_health')) {
                    const [fp] = args;
                    return d1Store.patch_health.get(fp) || null;
                  }
                  return null;
                },
                async all() {
                  if (sql.includes('FROM grievances')) {
                    // Check if query filters by queue_status = 'PROMOTED'
                    const filtered = d1Store.grievances.filter(g => g.queue_status === 'PROMOTED');
                    return { results: filtered };
                  }
                  return { results: [] };
                },
                async run() {
                  if (sql.includes('INSERT INTO grievances')) {
                    // args: [idVal, grievance_type, target, harness, fingerprint, symptom, workaround, env, sub, tier, applies_to, now, queue_status]
                    d1Store.grievances.push({
                      id: args[0],
                      grievance_type: args[1],
                      target: args[2],
                      harness: args[3],
                      fingerprint: args[4],
                      symptom: args[5],
                      workaround: args[6],
                      submitted_by: args[8],
                      verification_tier: args[9],
                      applies_to: args[10],
                      created_at: args[11],
                      queue_status: args[12]
                    });
                    return { meta: { changes: 1 } };
                  }
                  if (sql.includes('INSERT INTO rate_limits')) {
                    const [sub, win, count] = args;
                    const key = `${sub}:${win}`;
                    const curr = d1Store.rate_limits.get(key) || 0;
                    d1Store.rate_limits.set(key, curr + 1);
                    return { meta: { changes: 1 } };
                  }
                  if (sql.includes('INSERT INTO patch_health')) {
                    const [fp, ackInc, nackInc, cNackInc, status, updated_at] = args;
                    const existing = d1Store.patch_health.get(fp) || {
                      fingerprint: fp,
                      ack_count: 0,
                      nack_count: 0,
                      consecutive_nacks: 0,
                      status: 'ACTIVE'
                    };
                    if (args[5] === 'ACK') {
                      existing.ack_count += 1;
                      existing.consecutive_nacks = 0;
                    } else if (args[5] === 'NACK') {
                      existing.nack_count += 1;
                      existing.consecutive_nacks += 1;
                      if (existing.consecutive_nacks >= 3) {
                        existing.status = 'QUARANTINED';
                      }
                    }
                    d1Store.patch_health.set(fp, existing);
                    return { meta: { changes: 1 } };
                  }
                  return { meta: { changes: 1 } };
                }
              };
            }
          };
        }
      };

      const mockEnv = {
        DB: mockDb,
        ASSETS: {
          async fetch(req) {
            return new Response(JSON.stringify({
              workarounds: [
                { id: "static-1", target: "pydantic", symptom: "ZoneInfo error", workaround: "Upgrade", queue_status: "PROMOTED" }
              ]
            }), { status: 200, headers: { "Content-Type": "application/json" } });
          }
        }
      };

      // TEST 1: Submit canary payload via MCP
      const canaryReq = new Request('https://fmagenticl-registry.pages.dev/mcp', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'cf-connecting-ip': '203.0.113.42'
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {
            name: 'fmagenticl_submit_grievance',
            arguments: {
              grievance_type: 'AGENT_FRICTION',
              target: 'canary-exploit',
              symptom: 'CANARY_PAYLOAD_NEVER_SERVE',
              workaround: 'MALICIOUS_INJECTION_WORKAROUND',
              submitted_by: 'adversarial-bot',
              applies_to: 'both',
              environment: {}
            }
          }
        })
      });

      const res1 = await mcpMod.onRequestPost({ request: canaryReq, env: mockEnv });
      const rpc1 = await res1.json();
      if (rpc1.error) {
        console.error("rpc1 error:", JSON.stringify(rpc1.error));
      }
      const rpc1Data = JSON.parse(rpc1.result.content[0].text);

      // Verify canary is dead-dropped
      const storedCanary = d1Store.grievances.find(g => g.symptom === 'CANARY_PAYLOAD_NEVER_SERVE');

      // TEST 2: Query workarounds for 'canary-exploit'
      const unifiedResults = await mcpMod.getUnifiedWorkarounds(mockEnv, 'https://fmagenticl-registry.pages.dev', 'canary-exploit');

      // TEST 3: Reverse-DoS Rate Limiting on report_patch_outcome
      const fp = 'a'.repeat(64);
      function makeNackReq(ip) {
        return new Request('https://fmagenticl-registry.pages.dev/mcp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'cf-connecting-ip': ip },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 2,
            method: 'tools/call',
            params: {
              name: 'fmagenticl_report_patch_outcome',
              arguments: {
                fingerprint: fp,
                outcome: 'NACK',
                submitted_by: 'bot'
              }
            }
          })
        });
      }

      // Vote 1 from IP 198.51.100.99
      const vote1Res = await mcpMod.onRequestPost({ request: makeNackReq('198.51.100.99'), env: mockEnv });
      const vote1Rpc = await vote1Res.json();
      const vote1Data = JSON.parse(vote1Rpc.result.content[0].text);

      // Vote 2 from SAME IP (should be rate-limited, no increment)
      const vote2Res = await mcpMod.onRequestPost({ request: makeNackReq('198.51.100.99'), env: mockEnv });
      const vote2Rpc = await vote2Res.json();
      const vote2Data = JSON.parse(vote2Rpc.result.content[0].text);

      // Vote 3 from SAME IP
      const vote3Res = await mcpMod.onRequestPost({ request: makeNackReq('198.51.100.99'), env: mockEnv });
      const vote3Rpc = await vote3Res.json();
      const vote3Data = JSON.parse(vote3Rpc.result.content[0].text);

      const finalHealth = d1Store.patch_health.get(fp);

      process.stdout.write(JSON.stringify({
        rpc1Data,
        storedCanaryStatus: storedCanary?.queue_status,
        unifiedCountForCanary: unifiedResults.length,
        vote1Data,
        vote2Data,
        vote3Data,
        finalNackCount: finalHealth?.nack_count,
        finalConsecutiveNacks: finalHealth?.consecutive_nacks,
        finalPatchStatus: finalHealth?.status
      }));
    }

    run().catch(err => {
      console.error(err);
      process.exit(1);
    });
    """

    res = subprocess.run(
        [NODE, "--input-type=module", "-e", esm_test],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(REPO_ROOT),
        timeout=30,
    )
    assert res.returncode == 0, f"Airlock canary test failed: {res.stderr}"
    data = json.loads(res.stdout)

    # 1. Assert Dead-Drop Triage Response & Quarantine Storage
    assert data["rpc1Data"]["status"] == "RECEIVED"
    assert data["rpc1Data"]["review_tier"] == "MAINTAINER_TRIAGE_ONLY"
    assert "in-house audit" in data["rpc1Data"]["message"]
    assert data["storedCanaryStatus"] == "DEAD_LETTER_QUARANTINE"

    # 2. Assert Canary is NEVER served to readers
    assert data["unifiedCountForCanary"] == 0

    # 3. Assert Reverse-DoS Rate Limiting
    # First vote was accepted and counted
    assert data["vote1Data"]["nack_count"] == 1
    assert data["vote1Data"]["consecutive_nacks"] == 1

    # Second and third votes from same IP were rate limited
    assert data["vote2Data"]["rate_limited"] is True
    assert data["vote3Data"]["rate_limited"] is True

    # Health metrics froze at 1 NACK and status remains ACTIVE (not quarantined)
    assert data["finalNackCount"] == 1
    assert data["finalConsecutiveNacks"] == 1
    assert data["finalPatchStatus"] == "ACTIVE"
