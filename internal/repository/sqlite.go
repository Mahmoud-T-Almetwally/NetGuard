package repository

import (
	"log"
	"database/sql"
)

type DomainDB struct {
	db* sql.DB
}

type BlockedDomain struct {
	domain string
	action string
	source string
}

func (d* DomainDB) InitDB(s string){
	db, err := sql.Open("sqlite", s)

	if err != nil {
		log.Fatal(err)
	}

	log.Println("Connected to DB Successfully")

	d.db = db

	q := `
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    source TEXT,           -- 'stevenblack', 'user_manual', 'ai_auto_ban'
    action TEXT,           -- 'BLOCK', 'ALLOW'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    blocked_by TEXT,       -- 'database', 'ai_domain', 'content_scan'
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
	`

	if _, err = d.db.Exec(q); err != nil {
		log.Fatal(err)
	}

	log.Println("Initialized Tables Successfully")
}

func (d* DomainDB) GetAll() []string {

	if err := d.db.Ping(); err != nil {
		log.Fatal(err)
	}

	q := `
SELECT domain FROM rules;
	`

	rows, err := d.db.Query(q)

	if err != nil {
		log.Fatal(err)
	}

	domains := []string{}

	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			log.Fatal(err)
		}

		domains = append(domains, domain)

	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	return domains

}

func (d* DomainDB) Insert(domain BlockedDomain) {

	if err := d.db.Ping(); err != nil {
		log.Fatal(err)
	}

	sql := `
INSERT INTO rules(domain, source, action) VALUES (?, ?, ?);
	`

	if _, err := d.db.Exec(sql, domain.domain, domain.source, domain.action); err != nil {
		log.Fatal(err)
	}

	log.Println(domain.action, " Domain: ", domain.domain, " Source: ", domain.source)
}

func (d* DomainDB) BulkInsert(domains []BlockedDomain) {

	if err := d.db.Ping(); err != nil {
		log.Fatal(err)
	}

	sql := `
INSERT INTO rules(domain, source, action) VALUES (?, ?, ?);
	`

	for _, domain := range domains {
		_, err := d.db.Exec(sql, domain.domain, domain.source, domain.action)
		if err != nil{
			log.Fatal(err)
		}
	}

}