package rulehawk

import (
	"database/sql"
	"strings"
	"time"
)

// SQLiteStore persists RuleHawk configs. It lives in the rulehawk package (not
// the store package) and shares the same *sql.DB as the findings store.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore migrates the configs table and returns the store.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS rulehawk_configs (
    name       TEXT PRIMARY KEY,
    vendor     TEXT NOT NULL,
    current    TEXT NOT NULL DEFAULT '',
    baseline   TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL
);`); err != nil {
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) PutConfig(c Config) error {
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = time.Now()
	}
	_, err := s.db.Exec(`
INSERT INTO rulehawk_configs (name, vendor, current, baseline, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
    vendor = excluded.vendor, current = excluded.current,
    baseline = excluded.baseline, updated_at = excluded.updated_at`,
		c.Name, c.Vendor, c.Current, c.Baseline, c.UpdatedAt.UTC())
	return err
}

func (s *SQLiteStore) GetConfig(name string) (Config, bool, error) {
	row := s.db.QueryRow(
		`SELECT name, vendor, current, baseline, updated_at FROM rulehawk_configs WHERE name = ?`, name)
	c, err := scanConfig(row)
	if err == sql.ErrNoRows {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, false, err
	}
	return c, true, nil
}

func (s *SQLiteStore) ListConfigs() ([]Config, error) {
	rows, err := s.db.Query(`SELECT name, vendor, current, baseline, updated_at FROM rulehawk_configs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Config
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteConfig(name string) error {
	_, err := s.db.Exec(`DELETE FROM rulehawk_configs WHERE name = ?`, name)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanConfig(sc rowScanner) (Config, error) {
	var c Config
	var updated time.Time
	if err := sc.Scan(&c.Name, &c.Vendor, &c.Current, &c.Baseline, &updated); err != nil {
		return Config{}, err
	}
	c.UpdatedAt = updated
	c.HasBase = strings.TrimSpace(c.Baseline) != ""
	return c, nil
}
