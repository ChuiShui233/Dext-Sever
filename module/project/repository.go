package project

import (
    "Dext-Server/config"
    "Dext-Server/model"
    "database/sql"
    "fmt"
)

type Repository interface {
    // 聚合/计数
    CountProjects(username, query string) (int, error)
    // 分页列表
    ListProjects(username, query string, limit, offset int) ([]model.Project, error)
    // 全量列表（无分页）
    ListAllProjects(username, query string) ([]model.Project, error)

    // 创建/更新
    CreateProject(p *model.Project, username, userID string) (*model.Project, error)
    UpdateProject(p *model.Project, username string) (*model.Project, error)

    // 归属校验
    CountOwned(ids []int, username string) (int, error)

    // 级联删除（单个或批量），在事务中执行
    DeleteCascadeTx(tx *sql.Tx, projectID int, username string) error
}

type projectRepository struct{}

func NewProjectRepository() Repository { return &projectRepository{} }

func (r *projectRepository) CountProjects(username, query string) (int, error) {
    where := "create_by = ?"
    args := []interface{}{username}
    if query != "" {
        where += " AND project_name LIKE ?"
        args = append(args, "%"+query+"%")
    }
    var total int
    err := config.DB.QueryRow("SELECT COUNT(*) FROM projects WHERE "+where, args...).Scan(&total)
    return total, err
}

func (r *projectRepository) ListProjects(username, query string, limit, offset int) ([]model.Project, error) {
    where := "create_by = ?"
    args := []interface{}{username}
    if query != "" {
        where += " AND project_name LIKE ?"
        args = append(args, "%"+query+"%")
    }
    args = append(args, limit, offset)
    rows, err := config.DB.Query(`
        SELECT id, project_name, project_description, user_id, create_by,
               create_time, update_time, update_by
        FROM projects
        WHERE `+where+`
        ORDER BY create_time DESC
        LIMIT ? OFFSET ?`, args...)
    if err != nil { return nil, err }
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

func (r *projectRepository) ListAllProjects(username, query string) ([]model.Project, error) {
    where := "create_by = ?"
    args := []interface{}{username}
    if query != "" {
        where += " AND project_name LIKE ?"
        args = append(args, "%"+query+"%")
    }
    rows, err := config.DB.Query(`
        SELECT id, project_name, project_description, user_id, create_by,
               create_time, update_time, update_by
        FROM projects
        WHERE `+where+`
        ORDER BY create_time DESC`, args...)
    if err != nil { return nil, err }
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

func (r *projectRepository) CreateProject(p *model.Project, username, userID string) (*model.Project, error) {
    res, err := config.DB.Exec(`
        INSERT INTO projects (project_name, project_description, user_id, create_by, update_by)
        VALUES (?, ?, ?, ?, ?)
    `, p.ProjectName, p.ProjectDescription, userID, username, username)
    if err != nil { return nil, err }
    id, _ := res.LastInsertId()
    p.ID = int(id)
    p.UserID = userID
    p.UpdateBy = username
    return p, nil
}

func (r *projectRepository) UpdateProject(p *model.Project, username string) (*model.Project, error) {
    // 权限校验
    var cnt int
    if err := config.DB.QueryRow("SELECT COUNT(*) FROM projects WHERE id = ? AND create_by = ?", p.ID, username).Scan(&cnt); err != nil {
        return nil, err
    }
    if cnt == 0 { return nil, fmt.Errorf("无权更新该项目") }

    _, err := config.DB.Exec(`
        UPDATE projects
        SET project_name = ?, project_description = ?, update_time = CURRENT_TIMESTAMP, update_by = ?
        WHERE id = ? AND create_by = ?
    `, p.ProjectName, p.ProjectDescription, username, p.ID, username)
    if err != nil { return nil, err }

    var out model.Project
    err = config.DB.QueryRow(`
        SELECT id, project_name, project_description, user_id, create_by, create_time, update_time, update_by
        FROM projects WHERE id = ?
    `, p.ID).Scan(&out.ID, &out.ProjectName, &out.ProjectDescription, &out.UserID, &out.CreateBy, &out.CreateTime, &out.UpdateTime, &out.UpdateBy)
    if err != nil { return nil, err }
    return &out, nil
}

func (r *projectRepository) CountOwned(ids []int, username string) (int, error) {
    if len(ids) == 0 { return 0, nil }
    placeholders := ""
    args := make([]interface{}, 0, len(ids)+1)
    for i, id := range ids {
        if i > 0 { placeholders += "," }
        placeholders += "?"
        args = append(args, id)
    }
    args = append(args, username)
    var count int
    q := fmt.Sprintf("SELECT COUNT(*) FROM projects WHERE id IN (%s) AND create_by = ?", placeholders)
    if err := config.DB.QueryRow(q, args...).Scan(&count); err != nil { return 0, err }
    return count, nil
}

func (r *projectRepository) DeleteCascadeTx(tx *sql.Tx, projectID int, username string) error {
    // 关联数据按原有逻辑清理
    if _, err := tx.Exec("DELETE FROM answer_details WHERE answer_id IN (SELECT id FROM answers WHERE survey_id IN (SELECT id FROM surveys WHERE project_id = ?))", projectID); err != nil { return err }
    if _, err := tx.Exec("DELETE FROM answers WHERE survey_id IN (SELECT id FROM surveys WHERE project_id = ?)", projectID); err != nil { return err }
    if _, err := tx.Exec("DELETE FROM surveys WHERE project_id = ?", projectID); err != nil { return err }
    if _, err := tx.Exec("DELETE FROM projects WHERE id = ? AND create_by = ?", projectID, username); err != nil { return err }
    return nil
}
