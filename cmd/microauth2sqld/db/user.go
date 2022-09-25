package db

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"jochum.dev/jo-micro/buncomponent"
)

type User struct {
	bun.BaseModel `bun:"users,alias:u"`
	ID            uuid.UUID `bun:"id,pk,type:uuid,default:uuid_generate_v4()" json:"id" yaml:"id"`
	Username      string    `bun:"username" json:"username" yaml:"username"`
	Password      string    `bun:"password" json:"-" yaml:"-"`
	Email         string    `bun:"email" json:"email" yaml:"email"`
	Roles         []string  `bun:",array,scanonly" json:"roles" yaml:"roles"`

	// Timestamps
	CreatedAt time.Time    `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at" yaml:"created_at"`
	UpdatedAt bun.NullTime `bun:"updated_at" json:"updated_at" yaml:"updated_at"`

	// SoftDelete
	DeletedAt bun.NullTime `bun:"deleted_at,soft_delete,nullzero" json:"deleted_at" yaml:"deleted_at"`
}

func UserList(ctx context.Context, limit, offset uint64) ([]User, error) {
	// Get the data from the db.
	var users []User
	err := buncomponent.Must(ctx).Bun().NewSelect().
		Model(&users).
		ColumnExpr("u.*").
		ColumnExpr("array(SELECT r.name FROM users_roles AS ur LEFT JOIN roles AS r ON ur.role_id = r.id WHERE ur.user_id = u.id) AS roles").
		Limit(int(limit)).
		Offset(int(offset)).Scan(ctx)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func UserDetail(ctx context.Context, id string) (*User, error) {
	user := User{}
	err := buncomponent.Must(ctx).Bun().NewSelect().
		Model(&user).
		ColumnExpr("u.*").
		ColumnExpr("array(SELECT r.name FROM users_roles AS ur LEFT JOIN roles AS r ON ur.role_id = r.id WHERE ur.user_id = u.id) AS roles").
		Limit(1).
		Where("id = ?", id).
		Scan(ctx)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func UserDelete(ctx context.Context, id string) error {
	user := User{}
	_, err := buncomponent.Must(ctx).Bun().NewDelete().Model(&user).Where("id = ?", id).Exec(ctx)
	return err
}

func UserUpdateRoles(ctx context.Context, id string, roles []string) (*User, error) {
	// Check if all new roles exists
	rolesIds := make([]string, len(roles))
	for idx, role := range roles {
		id, err := RoleGetId(ctx, role)
		if err != nil {
			return nil, err
		}
		rolesIds[idx] = id
	}

	// Delete all current roles
	_, err := buncomponent.Must(ctx).Bun().NewDelete().Table("users_roles").Where("user_id = ?", id).Exec(ctx)
	if err != nil {
		return nil, err
	}

	// Exit out if user wants to delete all roles
	if len(roles) < 1 {
		return UserDetail(ctx, id)
	}

	// Reassign roles
	for _, roleId := range rolesIds {
		values := map[string]interface{}{
			"user_id": id,
			"role_id": roleId,
		}
		_, err = buncomponent.Must(ctx).Bun().NewInsert().Model(&values).TableExpr("users_roles").Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	return UserDetail(ctx, id)
}

func UserFindByUsername(ctx context.Context, username string) (*User, error) {
	user := User{}
	err := buncomponent.Must(ctx).Bun().NewSelect().
		Model(&user).
		ColumnExpr("u.*").
		ColumnExpr("array(SELECT r.name FROM users_roles AS ur LEFT JOIN roles AS r ON ur.role_id = r.id WHERE ur.user_id = u.id) AS roles").
		Limit(1).
		Where("u.username = ?", username).
		Scan(ctx)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func UserFindById(ctx context.Context, id string) (*User, error) {
	user := User{}
	err := buncomponent.Must(ctx).Bun().NewSelect().
		Model(&user).
		ColumnExpr("u.*").
		ColumnExpr("array(SELECT r.name FROM users_roles AS ur LEFT JOIN roles AS r ON ur.role_id = r.id WHERE ur.user_id = u.id) AS roles").
		Limit(1).
		Where("u.id = ?", id).
		Scan(ctx)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func UserCreate(ctx context.Context, username, password, email string, roles []string) (*User, error) {
	// Create the user
	user := User{}
	user.Username = username
	user.Password = password
	user.Email = email
	_, err := buncomponent.Must(ctx).Bun().NewInsert().Model(&user).Exec(ctx, &user)
	if err != nil {
		return nil, err
	}

	// Create roles
	_, err = UserUpdateRoles(ctx, user.ID.String(), roles)
	if err != nil {
		if len(user.ID.String()) > 0 {
			UserDelete(ctx, user.ID.String())
		}
		return nil, err
	}

	return &user, nil
}
