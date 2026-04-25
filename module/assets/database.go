package assets

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
)

func createAssetsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS assets_files (
			id VARCHAR(36) PRIMARY KEY,
			file_name VARCHAR(255) NOT NULL,
			original_name VARCHAR(255) NOT NULL,
			file_size BIGINT NOT NULL DEFAULT 0,
			content_type VARCHAR(128) NOT NULL,
			md5_hash VARCHAR(32),
			upload_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			bucket VARCHAR(64) NOT NULL,
			public_name VARCHAR(255) NOT NULL,
			owner VARCHAR(128) NOT NULL,
			url VARCHAR(512),
			UNIQUE KEY idx_bucket_public (bucket, public_name),
			KEY idx_owner (owner),
			KEY idx_upload_time (upload_time)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	if err != nil {
		return fmt.Errorf("创建 assets_files 表失败: %w", err)
	}
	return nil
}

func ScanFileMetadata(rows *sql.Rows) (*FileMetadata, error) {
	var m FileMetadata
	var uploadTime sql.NullTime
	err := rows.Scan(&m.ID, &m.FileName, &m.OriginalName, &m.FileSize, &m.ContentType,
		&m.MD5Hash, &uploadTime, &m.Bucket, &m.PublicName, &m.Owner, &m.URL)
	if err != nil {
		return nil, err
	}
	if uploadTime.Valid {
		m.UploadTime = uploadTime.Time
	}
	return &m, nil
}

func SaveFileToDB(db *sql.DB, m *FileMetadata) error {
	_, err := db.Exec(`
		INSERT INTO assets_files (id, file_name, original_name, file_size, content_type, md5_hash, upload_time, bucket, public_name, owner, url)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			file_name = VALUES(file_name),
			original_name = VALUES(original_name),
			file_size = VALUES(file_size),
			content_type = VALUES(content_type),
			md5_hash = VALUES(md5_hash),
			upload_time = VALUES(upload_time),
			owner = VALUES(owner),
			url = VALUES(url)`,
		m.ID, m.FileName, m.OriginalName, m.FileSize, m.ContentType,
		m.MD5Hash, m.UploadTime, m.Bucket, m.PublicName, m.Owner, m.URL)
	return err
}

func DeleteFileFromDB(db *sql.DB, bucket, publicName string) error {
	_, err := db.Exec("DELETE FROM assets_files WHERE bucket = ? AND public_name = ?", bucket, publicName)
	return err
}

func GetFileFromDB(db *sql.DB, bucket, publicName string) (*FileMetadata, error) {
	row := db.QueryRow(`
		SELECT id, file_name, original_name, file_size, content_type, md5_hash, upload_time, bucket, public_name, owner, url
		FROM assets_files
		WHERE bucket = ? AND public_name = ?`, bucket, publicName)

	var m FileMetadata
	var uploadTime sql.NullTime
	err := row.Scan(&m.ID, &m.FileName, &m.OriginalName, &m.FileSize, &m.ContentType,
		&m.MD5Hash, &uploadTime, &m.Bucket, &m.PublicName, &m.Owner, &m.URL)
	if err != nil {
		return nil, err
	}
	if uploadTime.Valid {
		m.UploadTime = uploadTime.Time
	}
	return &m, nil
}

func ListFilesByBucket(db *sql.DB, bucket string) ([]*FileMetadata, error) {
	rows, err := db.Query(`
		SELECT id, file_name, original_name, file_size, content_type, md5_hash, upload_time, bucket, public_name, owner, url
		FROM assets_files
		WHERE bucket = ?
		ORDER BY upload_time DESC`, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*FileMetadata
	for rows.Next() {
		m, err := ScanFileMetadata(rows)
		if err != nil {
			continue
		}
		files = append(files, m)
	}
	return files, nil
}

func GetPublicNameFromFileName(filename string) string {
	name := stripQualitySuffix(filename)
	name = stripExtension(name)
	return name
}

func BuildCompressedPath(storagePath, bucket, filename, quality string) string {
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	compressedName := fmt.Sprintf("%s_%s.jpg", name, quality)
	return filepath.Join(storagePath, bucket, "compressed", compressedName)
}

type CompressedFile struct {
	ID                 string
	OriginalID         string
	Bucket             string
	OriginalFileName   string
	CompressedFileName string
	Quality            string
	FileSize           int64
	ContentType        string
}

func SaveCompressedFile(db *sql.DB, c *CompressedFile) error {
	_, err := db.Exec(`
		INSERT INTO assets_compressed_files (id, original_id, bucket, original_filename, compressed_filename, quality, file_size, content_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			file_size = VALUES(file_size),
			created_at = CURRENT_TIMESTAMP`,
		c.ID, c.OriginalID, c.Bucket, c.OriginalFileName, c.CompressedFileName, c.Quality, c.FileSize, c.ContentType)
	return err
}

func GetCompressedFile(db *sql.DB, originalFilename, quality string) (*CompressedFile, error) {
	row := db.QueryRow(`
		SELECT id, original_id, bucket, original_filename, compressed_filename, quality, file_size, content_type
		FROM assets_compressed_files
		WHERE original_filename = ? AND quality = ?`, originalFilename, quality)

	var c CompressedFile
	err := row.Scan(&c.ID, &c.OriginalID, &c.Bucket, &c.OriginalFileName, &c.CompressedFileName, &c.Quality, &c.FileSize, &c.ContentType)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func DeleteCompressedFilesByOriginal(db *sql.DB, originalFilename string) error {
	_, err := db.Exec("DELETE FROM assets_compressed_files WHERE original_filename = ?", originalFilename)
	return err
}

func DeleteCompressedFile(db *sql.DB, originalFilename, quality string) error {
	_, err := db.Exec("DELETE FROM assets_compressed_files WHERE original_filename = ? AND quality = ?", originalFilename, quality)
	return err
}

func ListCompressedFilesByBucket(db *sql.DB, bucket string) ([]*CompressedFile, error) {
	rows, err := db.Query(`
		SELECT id, original_id, bucket, original_filename, compressed_filename, quality, file_size, content_type
		FROM assets_compressed_files
		WHERE bucket = ?`, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*CompressedFile
	for rows.Next() {
		var c CompressedFile
		err := rows.Scan(&c.ID, &c.OriginalID, &c.Bucket, &c.OriginalFileName, &c.CompressedFileName, &c.Quality, &c.FileSize, &c.ContentType)
		if err != nil {
			continue
		}
		files = append(files, &c)
	}
	return files, nil
}
