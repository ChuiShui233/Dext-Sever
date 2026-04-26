package project

import (
	"Dext-Server/config"
	"Dext-Server/model"
	"database/sql"
	"fmt"
	"strings"
)

type Repository interface {
	CountProjects(username, query string) (int, error)
	ListProjects(username, query string, limit, offset int) ([]model.Project, error)
	ListAllProjects(username, query string) ([]model.Project, error)
	CreateProject(p *model.Project, username, userID string) (*model.Project, error)
	UpdateProject(p *model.Project, username string) (*model.Project, error)
	CountOwned(ids []int, username string) (int, error)
	DeleteCascadeTx(tx *sql.Tx, projectID int, username string) error
}

type projectRepository struct{}

func NewProjectRepository() Repository {
	return &projectRepository{}
}

// -------------------------- 查询统计 --------------------------

func (r *projectRepository) CountProjects(username, queryParam string) (int, error) {
	query := "SELECT COUNT(*) FROM projects WHERE create_by = ?"
	args := []interface{}{username}

	if queryParam != "" {
		query += " AND project_name LIKE ?"
		args = append(args, "%"+queryParam+"%")
	}

	var total int
	if err := config.DB.QueryRow(query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// -------------------------- 分页/列表查询 --------------------------

func (r *projectRepository) ListProjects(username, queryParam string, limit, offset int) ([]model.Project, error) {
	baseQuery := "SELECT id, project_name, project_description, user_id, create_by, create_time, update_time, update_by FROM projects WHERE create_by = ?"
	args := []interface{}{username}

	if queryParam != "" {
		baseQuery += " AND project_name LIKE ?"
		args = append(args, "%"+queryParam+"%")
	}

	baseQuery += " ORDER BY create_time DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := config.DB.Query(baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Project
	for rows.Next() {
		var p model.Project
		if err := rows.Scan(&p.ID, &p.ProjectName, &p.ProjectDescription, &p.UserID,
			&p.CreateBy, &p.CreateTime, &p.UpdateTime, &p.UpdateBy); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (r *projectRepository) ListAllProjects(username, queryParam string) ([]model.Project, error) {
	baseQuery := "SELECT id, project_name, project_description, user_id, create_by, create_time, update_time, update_by FROM projects WHERE create_by = ?"
	args := []interface{}{username}

	if queryParam != "" {
		baseQuery += " AND project_name LIKE ?"
		args = append(args, "%"+queryParam+"%")
	}

	baseQuery += " ORDER BY create_time DESC"

	rows, err := config.DB.Query(baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Project
	for rows.Next() {
		var p model.Project
		if err := rows.Scan(&p.ID, &p.ProjectName, &p.ProjectDescription, &p.UserID,
			&p.CreateBy, &p.CreateTime, &p.UpdateTime, &p.UpdateBy); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// -------------------------- 创建/更新 --------------------------

func (r *projectRepository) CreateProject(p *model.Project, username, userID string) (*model.Project, error) {
	res, err := config.DB.Exec(
		`INSERT INTO projects (project_name, project_description, user_id, create_by, update_by)
         VALUES (?, ?, ?, ?, ?)`,
		p.ProjectName, p.ProjectDescription, userID, username, username,
	)
	if err != nil {
		return nil, err
	}

	id, _ := res.LastInsertId()
	p.ID = int(id)
	p.UserID = userID
	p.CreateBy = username
	p.UpdateBy = username
	return p, nil
}

func (r *projectRepository) UpdateProject(p *model.Project, username string) (*model.Project, error) {
	// 权限校验
	var cnt int
	if err := config.DB.QueryRow(
		"SELECT COUNT(*) FROM projects WHERE id = ? AND create_by = ?",
		p.ID, username,
	).Scan(&cnt); err != nil {
		return nil, err
	}
	if cnt == 0 {
		return nil, fmt.Errorf("无权更新该项目")
	}

	_, err := config.DB.Exec(
		`UPDATE projects
         SET project_name = ?, project_description = ?, update_time = CURRENT_TIMESTAMP, update_by = ?
         WHERE id = ? AND create_by = ?`,
		p.ProjectName, p.ProjectDescription, username, p.ID, username,
	)
	if err != nil {
		return nil, err
	}

	var out model.Project
	if err := config.DB.QueryRow(
		`SELECT id, project_name, project_description, user_id, create_by, create_time, update_time, update_by
         FROM projects WHERE id = ?`,
		p.ID,
	).Scan(&out.ID, &out.ProjectName, &out.ProjectDescription, &out.UserID,
		&out.CreateBy, &out.CreateTime, &out.UpdateTime, &out.UpdateBy); err != nil {
		return nil, err
	}
	return &out, nil
}

// -------------------------- 权限计数 --------------------------

func (r *projectRepository) CountOwned(ids []int, username string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, len(ids)+1)
	for i, id := range ids {
		args[i] = id
	}
	args[len(ids)] = username

	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM projects WHERE id IN (%s) AND create_by = ?",
		placeholders,
	)

	var count int
	if err := config.DB.QueryRow(query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// -------------------------- 级联删除 --------------------------

func (r *projectRepository) DeleteCascadeTx(tx *sql.Tx, projectID int, username string) error {
	queries := []struct {
		sql  string
		args []interface{}
	}{
		{
			`DELETE FROM answer_details 
             WHERE answer_id IN (
                 SELECT id FROM answers 
                 WHERE survey_id IN (
                     SELECT id FROM surveys 
                     WHERE project_id = ?
                 )
             )`,
			[]interface{}{projectID},
		},
		{
			`DELETE FROM answers 
             WHERE survey_id IN (
                 SELECT id FROM surveys 
                 WHERE project_id = ?
             )`,
			[]interface{}{projectID},
		},
		{
			`DELETE FROM surveys WHERE project_id = ?`,
			[]interface{}{projectID},
		},
		{
			`DELETE FROM projects WHERE id = ? AND create_by = ?`,
			[]interface{}{projectID, username},
		},
	}

	for _, q := range queries {
		if _, err := tx.Exec(q.sql, q.args...); err != nil {
			return err
		}
	}

	return nil
}
