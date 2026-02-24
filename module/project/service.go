package project

import (
    "Dext-Server/model"
    "database/sql"
    "errors"
)

type Service interface {
    // 查询
    List(username, query string, page, pageSize int) (items []model.Project, total, totalPages int, err error)
    ListAll(username, query string) ([]model.Project, error)

    // 变更
    Create(p *model.Project, username, userID string) (*model.Project, error)
    Update(p *model.Project, username string) (*model.Project, error)
    DeleteBatch(tx *sql.Tx, ids []int, username string) error
}

type service struct {
    repo Repository
}

func NewService(repo Repository) Service {
    return &service{repo: repo}
}

func (s *service) List(username, query string, page, pageSize int) (items []model.Project, total, totalPages int, err error) {
    if page < 1 { page = 1 }
    if pageSize < 1 || pageSize > 100 { pageSize = 10 }
    offset := (page - 1) * pageSize

    total, err = s.repo.CountProjects(username, query)
    if err != nil { return nil, 0, 0, err }

    items, err = s.repo.ListProjects(username, query, pageSize, offset)
    if err != nil { return nil, 0, 0, err }

    if pageSize == 0 { return items, total, 0, nil }
    totalPages = (total + pageSize - 1) / pageSize
    return
}

func (s *service) ListAll(username, query string) ([]model.Project, error) {
    return s.repo.ListAllProjects(username, query)
}

func (s *service) Create(p *model.Project, username, userID string) (*model.Project, error) {
    if p == nil { return nil, errors.New("nil project") }
    return s.repo.CreateProject(p, username, userID)
}

func (s *service) Update(p *model.Project, username string) (*model.Project, error) {
    if p == nil { return nil, errors.New("nil project") }
    return s.repo.UpdateProject(p, username)
}

func (s *service) DeleteBatch(tx *sql.Tx, ids []int, username string) error {
    if len(ids) == 0 { return nil }
    // 校验归属
    cnt, err := s.repo.CountOwned(ids, username)
    if err != nil { return err }
    if cnt != len(ids) { return errors.New("部分项目不存在或无权限删除") }

    for _, id := range ids {
        if err := s.repo.DeleteCascadeTx(tx, id, username); err != nil { return err }
    }
    return nil
}
