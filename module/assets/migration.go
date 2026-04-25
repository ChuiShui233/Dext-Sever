package assets

import (
	"database/sql"
	"log"
)

type Migration struct {
	Version int
	Name    string
	Up      func(*sql.DB) error
}

var migrations = []Migration{
	{1, "create_assets_table", createAssetsTable},
	{2, "create_compressed_files_table", createCompressedFilesTable},
}

func createCompressedFilesTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS assets_compressed_files (
			id VARCHAR(36) PRIMARY KEY,
			original_id VARCHAR(36) NOT NULL,
			bucket VARCHAR(64) NOT NULL,
			original_filename VARCHAR(255) NOT NULL,
			compressed_filename VARCHAR(255) NOT NULL,
			quality VARCHAR(16) NOT NULL,
			file_size BIGINT NOT NULL DEFAULT 0,
			content_type VARCHAR(64) NOT NULL DEFAULT 'image/jpeg',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY idx_original_quality (original_filename, quality),
			KEY idx_bucket (bucket)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	return err
}

func RunMigrations(db *sql.DB) error {
	if err := createMigrationsTable(db); err != nil {
		return err
	}

	for _, m := range migrations {
		applied, err := isMigrationApplied(db, m.Version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		log.Printf("[OpenAssets] 执行迁移 #%d: %s", m.Version, m.Name)
		if err := m.Up(db); err != nil {
			return err
		}
		if err := recordMigration(db, m.Version); err != nil {
			return err
		}
		log.Printf("[OpenAssets] 迁移 #%d 完成", m.Version)
	}
	return nil
}

func createMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS assets_migrations (
			version INT PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
	return err
}

func isMigrationApplied(db *sql.DB, version int) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM assets_migrations WHERE version = ?", version).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func recordMigration(db *sql.DB, version int) error {
	_, err := db.Exec("INSERT INTO assets_migrations (version) VALUES (?)", version)
	return err
}
