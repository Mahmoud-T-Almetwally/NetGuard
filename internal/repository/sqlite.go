package repository

import (
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type BlockedDomain struct {
	Domain string
	Action string
	Source string
}

type DomainDB struct {
	db *sql.DB
}

func (d *DomainDB) InitDB(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create directory for db: %v", err)
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return fmt.Errorf("could not open db: %v", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("could not connect to db (check permissions): %v", err)
	}

	d.db = db

	if _, err := d.db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return fmt.Errorf("failed to set WAL mode: %v", err)
	}

	q := `
	CREATE TABLE IF NOT EXISTS rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT UNIQUE NOT NULL,
		source TEXT,
		action TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at INTEGER
	);
	
	CREATE INDEX IF NOT EXISTS idx_domain ON rules(domain);
	
	CREATE TABLE IF NOT EXISTS metadata (
		key TEXT PRIMARY KEY, 
		value TEXT
	);
	`
	if _, err = d.db.Exec(q); err != nil {
		return fmt.Errorf("could not init tables: %v", err)
	}

	return nil
}

func (d *DomainDB) GetETag(source string) string {
	var val string
	_ = d.db.QueryRow("SELECT value FROM metadata WHERE key = ?", source+"_etag").Scan(&val)
	return val
}

func (d *DomainDB) UpdateETag(source, etag string) error {
	_, err := d.db.Exec("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)", source+"_etag", etag)
	return err
}

func (d *DomainDB) SyncUserRules(whitelist []string, blacklist []string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	upsert := func(domain, action string) error {
		query := `
		INSERT INTO rules (domain, source, action, batch_id) VALUES (?, 'user_manual', ?, 0)
		ON CONFLICT(domain) DO UPDATE SET 
			source = 'user_manual', 
			action = excluded.action;
		`
		_, err := tx.Exec(query, domain, action)
		return err
	}

	for _, domain := range blacklist {
		if err := upsert(domain, "BLOCK"); err != nil {
			return err
		}
	}

	for _, domain := range whitelist {
		if err := upsert(domain, "ALLOW"); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (d *DomainDB) StreamSync(dataStream <-chan BlockedDomain, source string) (int, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}

	defer tx.Rollback()
	importTime := time.Now().Unix()

	query := `
    INSERT INTO rules (domain, source, action, updated_at) 
    VALUES (?, ?, ?, ?)
    ON CONFLICT(domain) DO UPDATE SET 
        updated_at = excluded.updated_at,
        source = excluded.source;
    `
	stmt, err := tx.Prepare(query)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0

	for item := range dataStream {
		if _, err := stmt.Exec(item.Domain, source, item.Action, importTime); err != nil {
			log.Printf("Failed to insert %s: %v", item.Domain, err)
			continue
		}
		count++
	}

	pruneQuery := `DELETE FROM rules WHERE source = ? AND updated_at != ?`
	if _, err := tx.Exec(pruneQuery, source, importTime); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	log.Printf("Successfully streamed and inserted %d domains.", count)
	return count, nil
}

func (d *DomainDB) GetBlocklist() ([]string, error) {
	rows, err := d.db.Query("SELECT domain FROM rules WHERE action = 'BLOCK'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

func (d *DomainDB) GetRule(domain string) (*BlockedDomain, error) {
	var r BlockedDomain
	query := "SELECT domain, action, source FROM rules WHERE domain = ?"
	err := d.db.QueryRow(query, domain).Scan(&r.Domain, &r.Action, &r.Source)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (d *DomainDB) InsertOrUpdate(domain string, action string, source string) error {
	query := `
    INSERT INTO rules (domain, action, source, created_at) 
    VALUES (?, ?, ?, ?) 
    ON CONFLICT(domain) DO UPDATE SET 
        updated_at = excluded.created_at, 
        source = excluded.source,
        action = excluded.action;
    `
	stmt, err := d.db.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	importTime := time.Now().Unix()

	_, err = stmt.Exec(domain, action, source, importTime)

	return nil
}
