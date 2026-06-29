package media

import (
	"Dext-Server/config"
	"Dext-Server/model"
	"fmt"
	"time"
)

type Repository interface {
	// 问卷媒体文件相关
	CheckSurveyOwnership(surveyID, username string) (bool, error)
	SaveFileRecord(surveyID, username, fileName, fileURL string, fileSize int64, contentType string) (int64, error)
	UpdateFileURL(recordID int64, newURL string) error
	UpdateFileNameAndURL(recordID int64, newFileName, newURL string) error
	GetFileInfo(fileID, surveyID, username string) (string, error)
	DeleteFileRecord(fileID, surveyID string) error
	ListSurveyMediaFiles(surveyID string) ([]model.SurveyMediaFile, error)
	DeleteFileRecordByID(id int64) error

	// 问卷背景相关
	GetBackgroundID(surveyID int) (int, error)
	InsertBackground(surveyID int, desktopBg, mobileBg, username string, now string) error
	UpdateBackground(backgroundID int, desktopBg, mobileBg, now string) error
	UpdateSurveyTime(surveyID int, now string) error
	GetBackground(surveyID int) (string, string, error)

	// 头像相关
	UpdateAvatar(username, avatarURL string) error
}

type mediaRepository struct{}

func NewMediaRepository() Repository {
	return &mediaRepository{}
}

// ===== 问卷媒体文件相关 =====

func (r *mediaRepository) CheckSurveyOwnership(surveyID, username string) (bool, error) {
	var count int
	err := config.DB.QueryRow(`
		SELECT COUNT(*) FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE s.id = ? AND p.create_by = ?`, surveyID, username).Scan(&count)
	return count > 0, err
}

func (r *mediaRepository) SaveFileRecord(surveyID, username, fileName, fileURL string, fileSize int64, contentType string) (int64, error) {
	now := time.Now().Format("2006-01-02 15:04:05")
	result, err := config.DB.Exec(`
		INSERT INTO survey_assets_files (survey_id, username, file_name, file_url, file_size, content_type, upload_time)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		surveyID, username, fileName, fileURL, fileSize, contentType, now)
	if err != nil {
		return 0, fmt.Errorf("插入文件记录失败: %w", err)
	}
	return result.LastInsertId()
}

func (r *mediaRepository) UpdateFileURL(recordID int64, newURL string) error {
	_, err := config.DB.Exec("UPDATE survey_assets_files SET file_url = ? WHERE id = ?", newURL, recordID)
	return err
}

func (r *mediaRepository) UpdateFileNameAndURL(recordID int64, newFileName, newURL string) error {
	_, err := config.DB.Exec("UPDATE survey_assets_files SET file_name = ?, file_url = ? WHERE id = ?", newFileName, newURL, recordID)
	return err
}

func (r *mediaRepository) GetFileInfo(fileID, surveyID, username string) (string, error) {
	var fileName string
	err := config.DB.QueryRow(`
		SELECT smf.file_name FROM survey_assets_files smf
		JOIN surveys s ON smf.survey_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE smf.id = ? AND smf.survey_id = ? AND p.create_by = ?`,
		fileID, surveyID, username).Scan(&fileName)
	return fileName, err
}

func (r *mediaRepository) DeleteFileRecord(fileID, surveyID string) error {
	_, err := config.DB.Exec("DELETE FROM survey_assets_files WHERE id = ? AND survey_id = ?", fileID, surveyID)
	return err
}

func (r *mediaRepository) ListSurveyMediaFiles(surveyID string) ([]model.SurveyMediaFile, error) {
	rows, err := config.DB.Query(`
		SELECT id, file_name, file_url, file_size, content_type, upload_time
		FROM survey_assets_files
		WHERE survey_id = ?
		ORDER BY upload_time DESC`, surveyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []model.SurveyMediaFile
	for rows.Next() {
		var file model.SurveyMediaFile
		if err := rows.Scan(&file.ID, &file.FileName, &file.FileURL, &file.FileSize, &file.ContentType, &file.UploadTime); err != nil {
			continue
		}
		files = append(files, file)
	}
	return files, nil
}

func (r *mediaRepository) DeleteFileRecordByID(id int64) error {
	_, err := config.DB.Exec("DELETE FROM survey_assets_files WHERE id = ?", id)
	return err
}

// ===== 问卷背景相关 =====

func (r *mediaRepository) GetBackgroundID(surveyID int) (int, error) {
	var backgroundID int
	err := config.DB.QueryRow("SELECT id FROM survey_backgrounds WHERE survey_id = ?", surveyID).Scan(&backgroundID)
	return backgroundID, err
}

func (r *mediaRepository) InsertBackground(surveyID int, desktopBg, mobileBg, username string, now string) error {
	_, err := config.DB.Exec(`
		INSERT INTO survey_backgrounds (survey_id, desktop_background, mobile_background, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		surveyID, desktopBg, mobileBg, username, now, now)
	return err
}

func (r *mediaRepository) UpdateBackground(backgroundID int, desktopBg, mobileBg, now string) error {
	_, err := config.DB.Exec(`
		UPDATE survey_backgrounds
		SET desktop_background = ?, mobile_background = ?, updated_at = ?
		WHERE id = ?`,
		desktopBg, mobileBg, now, backgroundID)
	return err
}

func (r *mediaRepository) UpdateSurveyTime(surveyID int, now string) error {
	_, err := config.DB.Exec("UPDATE surveys SET update_time = ? WHERE id = ?", now, surveyID)
	return err
}

func (r *mediaRepository) GetBackground(surveyID int) (string, string, error) {
	var desktopBg, mobileBg string
	err := config.DB.QueryRow(`
		SELECT desktop_background, mobile_background FROM survey_backgrounds WHERE survey_id = ?`,
		surveyID).Scan(&desktopBg, &mobileBg)
	return desktopBg, mobileBg, err
}

// ===== 头像相关 =====

func (r *mediaRepository) UpdateAvatar(username, avatarURL string) error {
	_, err := config.DB.Exec("UPDATE users SET avatar_url = ? WHERE username = ?", avatarURL, username)
	return err
}
