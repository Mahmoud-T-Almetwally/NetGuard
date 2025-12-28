package repository

import (
	"database/sql"
	"fmt"
	"log"
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
	db, err := sql.Open("sqlite3", path) 
	if err != nil {
		return fmt.Errorf("could not open db: %v", err)
	}

	d.db = db

	_, _ = d.db.Exec("PRAGMA journal_mode=WAL;")

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

func (d *DomainDB) GetAll() ([]string, error) {
	rows, err := d.db.Query("SELECT domain FROM rules")
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