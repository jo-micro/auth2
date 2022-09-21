package ibun

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	migratePostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/jackc/pgx"
	"github.com/jackc/pgx/log/logrusadapter"
	"github.com/jackc/pgx/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/extra/bundebug"
	"go-micro.dev/v4/errors"

	"jochum.dev/jo-micro/auth2/internal/ilogger"
	"jochum.dev/jo-micro/auth2/shared/sutil"

	"github.com/urfave/cli/v2"
)

var initialized = false
var SQLDB *sql.DB
var Bun *bun.DB

func AppendFlags(flags []cli.Flag) []cli.Flag {
	flags = sutil.AppendFlag(flags, &cli.StringFlag{
		Name:    "auth2_database_url",
		Usage:   "bun Database URL",
		EnvVars: []string{"MICRO_AUTH2_DATABASE_URL"},
	})
	flags = sutil.AppendFlag(flags, &cli.BoolFlag{
		Name:        "auth2_database_debug",
		Usage:       "Set it to the debug the database queries",
		EnvVars:     []string{"MICRO_AUTH2_DATABASE_DEBUG"},
		DefaultText: "false",
		Value:       false,
	})
	flags = sutil.AppendFlag(flags, &cli.StringFlag{
		Name:    "auth2_migrations_table",
		Value:   "schema_migrations",
		Usage:   "Table to store migrations info",
		EnvVars: []string{"MICRO_AUTH2_MIGRATIONS_TABLE"},
	})
	flags = sutil.AppendFlag(flags, &cli.StringFlag{
		Name:    "auth2_migrations_dir",
		Value:   "/migrations",
		Usage:   "Folder which contains migrations",
		EnvVars: []string{"MICRO_AUTH2_MIGRATIONS_DIR"},
	})

	return flags
}

func Intialized() bool {
	return initialized
}

func Start(cli *cli.Context) error {
	if initialized {
		return nil
	}

	if cli.String("auth2_database_url") == "" {
		return errors.InternalServerError("internal/ibun.Start|sqltype.empty", "MICRO_AUTH2_DATABASE_URL is required")
	} else if strings.HasPrefix(cli.String("auth2_database_url"), "postgres://") {
		config, err := pgx.ParseURI(cli.String("auth2_database_url"))
		if err != nil {
			return err
		}

		config.PreferSimpleProtocol = true

		if ilogger.Intialized() {
			config.Logger = logrusadapter.NewLogger(ilogger.Logrus())
		}

		SQLDB = stdlib.OpenDB(config)
		driver, err := migratePostgres.WithInstance(SQLDB, &migratePostgres.Config{MigrationsTable: cli.String("auth2_migrations_table")})
		if err != nil {
			return err
		}

		m, err := migrate.NewWithDatabaseInstance(
			fmt.Sprintf("file://%s/postgres", cli.String("auth2_migrations_dir")),
			"postgres", driver)
		if err != nil {
			return errors.InternalServerError("internal/ibun.Start|migrate.NewWithDatabaseInstance", fmt.Sprintf("%s", err))
		}
		if err := m.Up(); err != migrate.ErrNoChange && err != nil {
			return errors.InternalServerError("internal/ibun.Start|migrate.Up", fmt.Sprintf("%s", err))
		}

		Bun = bun.NewDB(SQLDB, pgdialect.New())
		if Bun == nil {
			return errors.InternalServerError("internal/ibun.Start|bun.NewDB", "failed to create bun")
		}

		if cli.Bool("auth2_database_debug") {
			// Print all queries to stdout.
			Bun.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
		}
	} else {
		return errors.InternalServerError("internal/ibun.Start|sqltype", "unknown MICRO_AUTH2_DATABASE_URL type")
	}

	initialized = true
	return nil
}

func Stop() error {
	if err := SQLDB.Close(); err != nil {
		return err
	}

	if err := Bun.Close(); err != nil {
		return err
	}

	return nil
}
