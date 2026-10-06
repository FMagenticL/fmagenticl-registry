"""
FMagenticL - Pluggable storage engine with Redis, SQLite, or in-memory fallback.
"""
import os
import time
import json
import threading
import sqlite3
from typing import Optional, Dict, Any, List

# Bug 4: Pluggable redis dependency handling
try:
    import redis
    REDIS_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    REDIS_AVAILABLE = False

class StorageEngine:
    """
    Provides get/set operations for telemetry entries and resolution patches.
    Uses Redis if REDIS_URL is set, otherwise SQLite (default) or in-memory.
    """
    def __init__(self, db_path: str = "fmagenticl.db", redis_url: Optional[str] = None):
        self.db_path = db_path
        self.redis_url = redis_url or os.getenv("REDIS_URL")
        self.redis_client = None
        self.use_redis = False
        self.use_sqlite = False
        
        # Separate in-memory namespaces to prevent cache pollution
        self._memory_telemetry: Dict[str, str] = {}
        self._memory_resolve: Dict[str, str] = {}
        self._memory_meta: Dict[str, str] = {}
        self._memory_grievances: List[Dict[str, Any]] = []
        
        self._lock = threading.RLock()
        self._init_connection()

    def _init_connection(self):
        if REDIS_AVAILABLE and self.redis_url:
            try:
                self.redis_client = redis.Redis.from_url(self.redis_url, decode_responses=True)
                self.redis_client.ping()
                self.use_redis = True
                return
            except Exception:
                # Fall back to SQLite
                pass
        
        # Use SQLite with WAL mode for concurrency
        self.use_sqlite = True
        self._sqlite_local = threading.local()
        try:
            self._init_sqlite()
        except Exception:
            self.use_sqlite = False

    def _init_sqlite(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA wal_autocheckpoint=1000")
            conn.execute("PRAGMA synchronous=NORMAL")
            # Separate tables to resolve Bug 7
            conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                fingerprint TEXT PRIMARY KEY,
                entry_json TEXT NOT NULL,
                submitted_by TEXT DEFAULT 'anonymous',
                verification_tier TEXT DEFAULT 'claimed',
                foundational INTEGER DEFAULT 0,
                is_quarantined INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS resolve_cache (
                fingerprint TEXT PRIMARY KEY,
                patch_json TEXT NOT NULL,
                confidence REAL NOT NULL,
                submitted_by TEXT DEFAULT 'anonymous',
                verification_tier TEXT DEFAULT 'claimed',
                foundational INTEGER DEFAULT 0,
                is_quarantined INTEGER DEFAULT 0
            )
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                val TEXT NOT NULL
            )
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS grievances (
                id TEXT PRIMARY KEY,
                grievance_type TEXT NOT NULL,
                target TEXT NOT NULL,
                harness TEXT,
                fingerprint TEXT,
                entry_json TEXT NOT NULL,
                submitted_by TEXT NOT NULL,
                verification_tier TEXT DEFAULT 'claimed',
                created_at REAL NOT NULL
            )
            """)
            # Migrations for existing databases
            for col, col_def in [
                ("submitted_by", "TEXT DEFAULT 'anonymous'"),
                ("verification_tier", "TEXT DEFAULT 'claimed'"),
                ("foundational", "INTEGER DEFAULT 0"),
                ("is_quarantined", "INTEGER DEFAULT 0")
            ]:
                try:
                    conn.execute(f"ALTER TABLE telemetry ADD COLUMN {col} {col_def}")
                except Exception:
                    pass
                try:
                    conn.execute(f"ALTER TABLE resolve_cache ADD COLUMN {col} {col_def}")
                except Exception:
                    pass

            try:
                conn.execute("ALTER TABLE grievances ADD COLUMN verification_tier TEXT DEFAULT 'claimed'")
            except Exception:
                pass

            conn.execute("CREATE INDEX IF NOT EXISTS idx_grievances_target ON grievances (target)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_grievances_fingerprint ON grievances (fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_grievances_type ON grievances (grievance_type)")
            conn.commit()
            conn.close()

    def _get_sqlite_conn(self, read_only: bool = False):
        attr = 'read_conn' if read_only else 'write_conn'
        if not hasattr(self._sqlite_local, attr):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")
            if read_only:
                try:
                    conn.execute("PRAGMA query_only=ON")
                except Exception:
                    pass
            setattr(self._sqlite_local, attr, conn)
        return getattr(self._sqlite_local, attr)

    def batch_write_telemetry(self, batch: List[Dict[str, Any]]):
        """Perform batch insert into telemetry and resolve_cache in a single atomic transaction."""
        if not batch:
            return
        if self.use_sqlite:
            with self._lock:
                conn = self._get_sqlite_conn(read_only=False)
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    for item in batch:
                        fp = item["fingerprint"]
                        fp_hex = fp.split(":")[-1]
                        entry_json = item["entry_json"]
                        patch = item["patch"]
                        conf = item.get("confidence", 0.98)
                        sub_by = item.get("submitted_by", "anonymous")
                        tier = item.get("verification_tier", "claimed")
                        foundational = 1 if item.get("foundational", False) else 0
                        is_quarantined = 1 if item.get("is_quarantined", False) else 0
                        
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO telemetry 
                            (fingerprint, entry_json, submitted_by, verification_tier, foundational, is_quarantined) 
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (fp_hex, entry_json, sub_by, tier, foundational, is_quarantined)
                        )
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO resolve_cache 
                            (fingerprint, patch_json, confidence, submitted_by, verification_tier, foundational, is_quarantined) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (fp_hex, json.dumps(patch), conf, sub_by, tier, foundational, is_quarantined)
                        )
                    conn.commit()
                except Exception as e:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    print(f"[FMagenticL Storage] Batch write failed: {e}")
        else:
            for item in batch:
                fp_hex = item["fingerprint"].split(":")[-1]
                self.set(fp_hex, item["entry_json"], submitted_by=item.get("submitted_by", "anonymous"), verification_tier=item.get("verification_tier", "claimed"), foundational=item.get("foundational", False), is_quarantined=item.get("is_quarantined", False))
                self.set_resolve_cache(fp_hex, item["patch"], confidence=item.get("confidence", 0.98), submitted_by=item.get("submitted_by", "anonymous"), verification_tier=item.get("verification_tier", "claimed"), foundational=item.get("foundational", False), is_quarantined=item.get("is_quarantined", False))

    def get(self, key: str) -> Optional[str]:
        """Retrieve a JSON string from telemetry."""
        if self.use_redis:
            return self.redis_client.get(f"telemetry:{key}")
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn(read_only=True)
                cur = conn.execute("SELECT entry_json FROM telemetry WHERE fingerprint=?", (key,))
                row = cur.fetchone()
                if row:
                    return row[0]
            except Exception:
                return None
        else:
            with self._lock:
                return self._memory_telemetry.get(key)
        return None

    def set(
        self,
        key: str,
        value: str,
        submitted_by: str = "anonymous",
        verification_tier: str = "claimed",
        foundational: bool = False,
        is_quarantined: bool = False
    ):
        """Store a JSON string in telemetry."""
        if self.use_redis:
            self.redis_client.set(f"telemetry:{key}", value)
        elif self.use_sqlite:
            with self._lock:
                try:
                    conn = self._get_sqlite_conn()
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO telemetry 
                        (fingerprint, entry_json, submitted_by, verification_tier, foundational, is_quarantined) 
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (key, value, submitted_by, verification_tier, 1 if foundational else 0, 1 if is_quarantined else 0)
                    )
                    conn.commit()
                except Exception:
                    pass
        else:
            with self._lock:
                self._memory_telemetry[key] = value

    def set_meta(self, key: str, value: str):
        """Store internal metadata (Bug 7: separates system keys from telemetry stats)."""
        if self.use_redis:
            self.redis_client.set(f"meta:{key}", value)
        elif self.use_sqlite:
            with self._lock:
                try:
                    conn = self._get_sqlite_conn()
                    conn.execute("INSERT OR REPLACE INTO meta (key, val) VALUES (?, ?)", (key, value))
                    conn.commit()
                except Exception:
                    pass
        else:
            with self._lock:
                self._memory_meta[key] = value

    def get_meta(self, key: str) -> Optional[str]:
        """Retrieve internal metadata."""
        if self.use_redis:
            return self.redis_client.get(f"meta:{key}")
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                cur = conn.execute("SELECT val FROM meta WHERE key=?", (key,))
                row = cur.fetchone()
                if row:
                    return row[0]
            except Exception:
                return None
        else:
            with self._lock:
                return self._memory_meta.get(key)
        return None

    def set_resolve_cache(
        self,
        fingerprint: str,
        patch: Dict[str, Any],
        confidence: float,
        submitted_by: str = "anonymous",
        verification_tier: str = "claimed",
        foundational: bool = False,
        is_quarantined: bool = False
    ):
        """Store a resolve cache entry (compact patch)."""
        patch_json = json.dumps(patch)
        if self.use_redis:
            self.redis_client.set(f"resolve:{fingerprint}", json.dumps({
                "patch": patch,
                "confidence": confidence,
                "submitted_by": submitted_by,
                "verification_tier": verification_tier,
                "foundational": foundational,
                "is_quarantined": is_quarantined
            }))
        elif self.use_sqlite:
            with self._lock:
                try:
                    conn = self._get_sqlite_conn()
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO resolve_cache 
                        (fingerprint, patch_json, confidence, submitted_by, verification_tier, foundational, is_quarantined) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (fingerprint, patch_json, confidence, submitted_by, verification_tier, 1 if foundational else 0, 1 if is_quarantined else 0)
                    )
                    conn.commit()
                except Exception:
                    pass
        else:
            with self._lock:
                self._memory_resolve[fingerprint] = json.dumps({
                    "patch": patch,
                    "confidence": confidence,
                    "submitted_by": submitted_by,
                    "verification_tier": verification_tier,
                    "foundational": foundational,
                    "is_quarantined": is_quarantined
                })

    def set_memory_cache(
        self,
        fingerprint: str,
        entry_json: str,
        patch: Dict[str, Any],
        confidence: float = 0.98,
        submitted_by: str = "anonymous",
        verification_tier: str = "claimed",
        foundational: bool = False,
        is_quarantined: bool = False
    ):
        """Immediately buffer entry in memory for zero-latency concurrent reads."""
        with self._lock:
            self._memory_telemetry[fingerprint] = entry_json
            self._memory_resolve[fingerprint] = json.dumps({
                "patch": patch,
                "confidence": confidence,
                "submitted_by": submitted_by,
                "verification_tier": verification_tier,
                "foundational": foundational,
                "is_quarantined": is_quarantined
            })

    def get_resolve(self, fingerprint: str, include_quarantined: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieve a resolve cache entry as dict. Quarantined entries ignored unless include_quarantined=True."""
        res = None
        # Check in-memory buffer first
        with self._lock:
            mem_data = self._memory_resolve.get(fingerprint)
            if mem_data:
                res = json.loads(mem_data)

        if not res:
            if self.use_redis:
                data = self.redis_client.get(f"resolve:{fingerprint}")
                if data:
                    res = json.loads(data)
            elif self.use_sqlite:
                try:
                    conn = self._get_sqlite_conn(read_only=True)
                    cur = conn.execute(
                        "SELECT patch_json, confidence, submitted_by, verification_tier, foundational, is_quarantined FROM resolve_cache WHERE fingerprint=?",
                        (fingerprint,)
                    )
                    row = cur.fetchone()
                    if row:
                        res = {
                            "patch": json.loads(row[0]),
                            "confidence": row[1],
                            "submitted_by": row[2] if len(row) > 2 and row[2] else "anonymous",
                            "verification_tier": row[3] if len(row) > 3 and row[3] else "claimed",
                            "foundational": bool(row[4]) if len(row) > 4 and row[4] else False,
                            "is_quarantined": bool(row[5]) if len(row) > 5 and row[5] else False
                        }
                except Exception:
                    return None
        else:
            with self._lock:
                data = self._memory_resolve.get(fingerprint)
                if data:
                    res = json.loads(data)

        if not res:
            return None

        # Normalize fields
        if "submitted_by" not in res:
            res["submitted_by"] = "anonymous"
        if "verification_tier" not in res:
            res["verification_tier"] = "claimed"
        if "foundational" not in res:
            res["foundational"] = False
        if "is_quarantined" not in res:
            res["is_quarantined"] = False

        # Filter out quarantined if not requested
        if res["is_quarantined"] and not include_quarantined:
            return None

        return res

    def exists(self, key: str) -> bool:
        """Check if key exists in telemetry (Bug 14: adds exception handling)."""
        if self.use_redis:
            try:
                return self.redis_client.exists(f"telemetry:{key}") > 0
            except Exception:
                return False
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                cur = conn.execute("SELECT 1 FROM telemetry WHERE fingerprint=?", (key,))
                return cur.fetchone() is not None
            except Exception:
                return False
        else:
            with self._lock:
                return key in self._memory_telemetry

    def get_all_entries(self) -> List[Dict[str, Any]]:
        """Return list of all telemetry entries (Bug 7/8: no longer includes resolve cache or meta)."""
        if self.use_redis:
            try:
                keys = self.redis_client.keys("telemetry:*")
                entries = []
                for k in keys:
                    data = self.redis_client.get(k)
                    if data:
                        entries.append(json.loads(data))
                return entries
            except Exception:
                return []
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                cur = conn.execute("SELECT entry_json FROM telemetry")
                return [json.loads(row[0]) for row in cur.fetchall()]
            except Exception:
                return []
        else:
            with self._lock:
                return [json.loads(v) for v in self._memory_telemetry.values()]

    def dbsize(self) -> int:
        """Return count of telemetry records (resolves Bug 15/test compatibility)."""
        if self.use_redis:
            try:
                return len(self.redis_client.keys("telemetry:*"))
            except Exception:
                return 0
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                cur = conn.execute("SELECT COUNT(*) FROM telemetry")
                return cur.fetchone()[0]
            except Exception:
                return 0
        else:
            with self._lock:
                return len(self._memory_telemetry)

    def add_grievance(
        self,
        grievance_id: str,
        grievance_type: str,
        target: str,
        harness: Optional[str],
        fingerprint: Optional[str],
        entry_json: str,
        submitted_by: str,
        created_at: float,
        verification_tier: str = "claimed"
    ):
        """Store a structured grievance in the registry."""
        record = {
            "id": grievance_id,
            "grievance_type": grievance_type,
            "target": target,
            "harness": harness,
            "fingerprint": fingerprint,
            "entry_json": entry_json,
            "submitted_by": submitted_by,
            "verification_tier": verification_tier,
            "created_at": created_at
        }
        if self.use_redis:
            self.redis_client.set(f"grievance:{grievance_id}", json.dumps(record))
            self.redis_client.sadd(f"grievances_by_target:{target}", grievance_id)
            if fingerprint:
                self.redis_client.sadd(f"disputes_by_fp:{fingerprint}", grievance_id)
        elif self.use_sqlite:
            with self._lock:
                try:
                    conn = self._get_sqlite_conn()
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO grievances 
                        (id, grievance_type, target, harness, fingerprint, entry_json, submitted_by, verification_tier, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (grievance_id, grievance_type, target, harness, fingerprint, entry_json, submitted_by, verification_tier, created_at)
                    )
                    conn.commit()
                except Exception:
                    pass
        else:
            with self._lock:
                self._memory_grievances.append(record)

    def get_grievances_by_target(self, target: str) -> List[Dict[str, Any]]:
        """Return all grievances associated with a specific infrastructure target."""
        if self.use_redis:
            try:
                ids = self.redis_client.smembers(f"grievances_by_target:{target}")
                results = []
                for gid in ids:
                    raw = self.redis_client.get(f"grievance:{gid}")
                    if raw:
                        rec = json.loads(raw)
                        results.append(json.loads(rec["entry_json"]))
                return sorted(results, key=lambda x: x.get("created_at", 0), reverse=True)
            except Exception:
                return []
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                cur = conn.execute(
                    "SELECT entry_json FROM grievances WHERE target=? ORDER BY created_at DESC",
                    (target,)
                )
                return [json.loads(row[0]) for row in cur.fetchall()]
            except Exception:
                return []
        else:
            with self._lock:
                matched = [
                    json.loads(g["entry_json"])
                    for g in self._memory_grievances
                    if g["target"] == target
                ]
                return sorted(matched, key=lambda x: x.get("created_at", 0), reverse=True)

    def get_disputes_by_fingerprint(self, fingerprint: str) -> List[Dict[str, Any]]:
        """Return all PATCH_DISPUTE grievances filed against a specific patch fingerprint."""
        if self.use_redis:
            try:
                ids = self.redis_client.smembers(f"disputes_by_fp:{fingerprint}")
                results = []
                for gid in ids:
                    raw = self.redis_client.get(f"grievance:{gid}")
                    if raw:
                        rec = json.loads(raw)
                        results.append(json.loads(rec["entry_json"]))
                return sorted(results, key=lambda x: x.get("created_at", 0), reverse=True)
            except Exception:
                return []
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                cur = conn.execute(
                    "SELECT entry_json FROM grievances WHERE fingerprint=? AND grievance_type='PATCH_DISPUTE' ORDER BY created_at DESC",
                    (fingerprint,)
                )
                return [json.loads(row[0]) for row in cur.fetchall()]
            except Exception:
                return []
        else:
            with self._lock:
                matched = [
                    json.loads(g["entry_json"])
                    for g in self._memory_grievances
                    if g["fingerprint"] == fingerprint and g["grievance_type"] == "PATCH_DISPUTE"
                ]
                return sorted(matched, key=lambda x: x.get("created_at", 0), reverse=True)

    def count_disputes(self, fingerprint: str) -> int:
        """Count total active disputes against a patch fingerprint."""
        if self.use_redis:
            try:
                return self.redis_client.scard(f"disputes_by_fp:{fingerprint}")
            except Exception:
                return 0
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                cur = conn.execute(
                    "SELECT COUNT(*) FROM grievances WHERE fingerprint=? AND grievance_type='PATCH_DISPUTE'",
                    (fingerprint,)
                )
                return cur.fetchone()[0]
            except Exception:
                return 0
        else:
            with self._lock:
                return sum(
                    1 for g in self._memory_grievances
                    if g["fingerprint"] == fingerprint and g["grievance_type"] == "PATCH_DISPUTE"
                )

    def count_weighted_disputes(self, fingerprint: str, client_os: Optional[str] = None) -> float:
        """
        Count environment-weighted disputes for a patch fingerprint.
        - Exact OS match: 1.0
        - Different OS: 0.3
        - No OS provided/available: 0.0 (or 1.0 default if client_os is None)
        """
        disputes = self.get_disputes_by_fingerprint(fingerprint)
        if not disputes:
            return 0.0
        if not client_os:
            return float(len(disputes))

        total_weight = 0.0
        c_os = client_os.lower().strip()
        for d in disputes:
            env = d.get("environment") or {}
            d_os = env.get("os", "").lower().strip() if isinstance(env, dict) else ""
            if not d_os:
                total_weight += 0.0
            elif d_os == c_os or (c_os.startswith("win") and d_os.startswith("win")) or (c_os.startswith("linux") and d_os.startswith("linux")) or (c_os.startswith("darwin") and d_os.startswith("darwin")):
                total_weight += 1.0
            else:
                total_weight += 0.3
        return round(total_weight, 2)

    def count_grievances(self, target: str) -> int:
        """Count total open grievances against a target."""
        if self.use_redis:
            try:
                return self.redis_client.scard(f"grievances_by_target:{target}")
            except Exception:
                return 0
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                cur = conn.execute(
                    "SELECT COUNT(*) FROM grievances WHERE target=?",
                    (target,)
                )
                return cur.fetchone()[0]
            except Exception:
                return 0
        else:
            with self._lock:
                return sum(1 for g in self._memory_grievances if g["target"] == target)

    def count_all_grievances(self) -> int:
        """Count total grievances across all targets."""
        if self.use_redis:
            try:
                keys = self.redis_client.keys("grievance:*")
                return len(keys)
            except Exception:
                return 0
        elif self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                cur = conn.execute("SELECT COUNT(*) FROM grievances")
                return cur.fetchone()[0]
            except Exception:
                return 0
        else:
            with self._lock:
                return len(self._memory_grievances)

    def get_scoreboard_data(self) -> Dict[str, Any]:
        """
        Internal Scoreboard calculation:
        Aggregates submissions per model, verification breakdown, disputes filed/received,
        average trust score, and composite rank. ZERO lineage tracking.
        """
        model_stats: Dict[str, Dict[str, Any]] = {}

        def get_or_create(m: str):
            clean_m = m.strip() if m else "anonymous"
            if clean_m not in model_stats:
                model_stats[clean_m] = {
                    "model": clean_m,
                    "patches_submitted": 0,
                    "patches_verified": 0,
                    "patches_quarantined": 0,
                    "verification_tiers": {"provider-key": 0, "weight-hashed": 0, "self-attested": 0, "claimed": 0},
                    "trust_scores": [],
                    "disputes_filed": 0,
                    "disputes_received": 0,
                }
            return model_stats[clean_m]

        if self.use_sqlite:
            try:
                conn = self._get_sqlite_conn()
                # 1. Telemetry and resolve stats
                cur = conn.execute("SELECT fingerprint, submitted_by, verification_tier, is_quarantined FROM telemetry")
                rows = cur.fetchall()
                for fp, sub_by, v_tier, is_quar in rows:
                    m = sub_by or "anonymous"
                    tier = v_tier or "claimed"
                    stat = get_or_create(m)
                    stat["patches_submitted"] += 1
                    stat["verification_tiers"][tier] = stat["verification_tiers"].get(tier, 0) + 1
                    if is_quar:
                        stat["patches_quarantined"] += 1
                    else:
                        stat["patches_verified"] += 1

                    # Compute dispute & trust score for this patch
                    fp_hex = fp.split(":")[-1]
                    res = self.get_resolve(fp_hex, include_quarantined=True)
                    if res:
                        conf = res.get("confidence", 0.5)
                        disp_count = self.count_disputes(fp_hex) + self.count_disputes(fp)
                        stat["disputes_received"] += disp_count
                        ts = max(0.05, round(conf - (0.15 * disp_count), 2))
                        stat["trust_scores"].append(ts)

                # 2. Grievances stats
                g_cur = conn.execute("SELECT submitted_by, verification_tier, grievance_type FROM grievances")
                for g_sub, g_tier, g_type in g_cur.fetchall():
                    m = g_sub or "anonymous"
                    stat = get_or_create(m)
                    stat["disputes_filed"] += 1
            except Exception:
                pass

        # Calculate averages and composite ranks
        leaderboard = []
        for m, s in model_stats.items():
            scores = s["trust_scores"]
            avg_trust = round(sum(scores) / len(scores), 2) if scores else 0.85
            s["average_trust_score"] = avg_trust
            # Composite rank calculation (positive leadership framing)
            composite = round(
                (s["patches_verified"] * avg_trust)
                - (s["disputes_received"] * 0.5)
                + (s["disputes_filed"] * 0.1),
                2
            )
            s["composite_score"] = composite
            del s["trust_scores"]
            leaderboard.append(s)

        leaderboard.sort(key=lambda x: x["composite_score"], reverse=True)
        for idx, item in enumerate(leaderboard, 1):
            item["rank"] = idx

        return {
            "generated_at": time.time() if 'time' in globals() else 0.0,
            "total_models": len(leaderboard),
            "leaderboard": leaderboard
        }

    def get_public_scoreboard(self, include_unverified: bool = False) -> Dict[str, Any]:
        """
        Public Scoreboard:
        Positive leadership framing. Gating rule: only models with provider-key,
        weight-hashed, or self-attested verified submissions appear by default.
        """
        data = self.get_scoreboard_data()
        raw_leaderboard = data.get("leaderboard", [])

        public_leaderboard = []
        for entry in raw_leaderboard:
            tiers = entry.get("verification_tiers", {})
            verified_count = tiers.get("provider-key", 0) + tiers.get("weight-hashed", 0) + tiers.get("self-attested", 0)
            
            # Gating rule: filter unverified-only models unless include_unverified=True
            if not include_unverified and verified_count == 0:
                continue

            public_leaderboard.append({
                "model": entry["model"],
                "patches_verified": entry["patches_verified"],
                "average_trust_score": entry["average_trust_score"],
                "composite_score": entry["composite_score"],
                "verification_level": "verified" if verified_count > 0 else "unverified"
            })

        public_leaderboard.sort(key=lambda x: x["composite_score"], reverse=True)
        for idx, item in enumerate(public_leaderboard, 1):
            item["rank"] = idx

        return {
            "title": "FMagenticL Collective Intelligence Leaderboard",
            "description": "Verified failure resolution contributions across autonomous AI models.",
            "total_models": len(public_leaderboard),
            "leaderboard": public_leaderboard
        }


