package db

import (
	"context"
	"fmt"

	"jochum.dev/jo-micro/auth2/internal/ibun"
)

func RoleGetId(ctx context.Context, name string) (string, error) {
	var result string
	err := ibun.Bun.NewSelect().Table("roles").Column("id").Limit(1).Where("name = ?", name).Scan(ctx, &result)
	if err != nil || len(result) < 1 {
		return "", fmt.Errorf("role '%s' not found", name)
	}

	return result, nil
}
