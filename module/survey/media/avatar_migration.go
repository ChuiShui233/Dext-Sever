package media

import (
	"Dext-Server/config"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// MigrateAvatars 把 ./uploads/avatars/ 下的旧头像物理文件复制到 ./assets_storage/user-avatars/，
// 并把 users.avatar_url 从 /uploads/avatars/xxx.ext 改写为 /openassets/files/user-avatars/xxx。
// 迁移是幂等的：再次启动时 URL 已经是新格式就跳过。
func MigrateAvatars() {
	const (
		srcDir    = "./uploads/avatars"
		dstDir    = "./assets_storage/user-avatars"
		newPrefix = "/openassets/files/user-avatars/"
		oldPrefix = "/uploads/avatars/"
	)

	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		return
	}
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		log.Printf("[AvatarMigrate] 创建目标目录失败: %v", err)
		return
	}

	rows, err := config.DB.Query(
		`SELECT id, avatar_url FROM users WHERE avatar_url LIKE ?`,
		oldPrefix+"%",
	)
	if err != nil {
		log.Printf("[AvatarMigrate] 查询旧头像失败: %v", err)
		return
	}
	defer rows.Close()

	type pending struct {
		id           string
		newURL       string
		physicalName string
	}
	var jobs []pending
	for rows.Next() {
		var id, url string
		if err := rows.Scan(&id, &url); err != nil {
			continue
		}
		base := strings.TrimPrefix(url, oldPrefix) // e.g. "abc123.jpg"
		ext := filepath.Ext(base)                  // ".jpg"
		publicName := strings.TrimSuffix(base, ext)
		physicalName := publicName + ext
		jobs = append(jobs, pending{
			id:           id,
			newURL:       newPrefix + publicName,
			physicalName: physicalName,
		})
	}

	if len(jobs) == 0 {
		log.Println("[AvatarMigrate] 没有需要迁移的旧头像")
		return
	}

	copied := 0
	updated := 0
	for _, j := range jobs {
		src := filepath.Join(srcDir, j.physicalName)
		dst := filepath.Join(dstDir, j.physicalName)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			log.Printf("[AvatarMigrate] 源文件缺失，跳过: %s", src)
		} else if _, err := os.Stat(dst); err == nil {
			// 目标已存在，不覆盖
		} else if err := copyFileAtomic(src, dst); err != nil {
			log.Printf("[AvatarMigrate] 复制失败 %s → %s: %v", src, dst, err)
		} else {
			copied++
		}
		if res, err := config.DB.Exec(`UPDATE users SET avatar_url = ? WHERE id = ?`, j.newURL, j.id); err != nil {
			log.Printf("[AvatarMigrate] 更新数据库失败: id=%s, err=%v", j.id, err)
		} else if n, _ := res.RowsAffected(); n > 0 {
			updated++
		}
	}
	log.Printf("[AvatarMigrate] 头像迁移完成: 复制 %d 个文件，更新 %d 条数据库记录（共 %d 个待处理）", copied, updated, len(jobs))
}

func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
