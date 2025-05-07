CREATE TABLE IF NOT EXISTS osint_results (
  id         SERIAL PRIMARY KEY,
  target     TEXT NOT NULL,
  category   TEXT NOT NULL,
  data       JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
