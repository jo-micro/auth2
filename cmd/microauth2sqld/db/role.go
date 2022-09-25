package db

import (
	"context"
	"fmt"

	"jochum.dev/jo-micro/buncomponent"
	"jochum.dev/jo-micro/components"
)

func RoleGetId(cReg *components.Registry, ctx context.Context, name string) (string, error) {
	var result string
	err := buncomponent.MustReg(cReg).Bun().NewSelect().Table("roles").Column("id").Limit(1).Where("name = ?", name).Scan(ctx, &result)
	if err != nil || len(result) < 1 {
		return "", fmt.Errorf("role '%s' not found", name)
	}

	return result, nil
}
