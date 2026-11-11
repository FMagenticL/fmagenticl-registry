-- Migration 0002: Add 64-bit FNV-1a SimHash LSH bands to grievances table
ALTER TABLE grievances ADD COLUMN simhash_b0 INTEGER;
ALTER TABLE grievances ADD COLUMN simhash_b1 INTEGER;
ALTER TABLE grievances ADD COLUMN simhash_b2 INTEGER;
ALTER TABLE grievances ADD COLUMN simhash_b3 INTEGER;

CREATE INDEX IF NOT EXISTS idx_grievances_b0 ON grievances(simhash_b0);
CREATE INDEX IF NOT EXISTS idx_grievances_b1 ON grievances(simhash_b1);
CREATE INDEX IF NOT EXISTS idx_grievances_b2 ON grievances(simhash_b2);
CREATE INDEX IF NOT EXISTS idx_grievances_b3 ON grievances(simhash_b3);
