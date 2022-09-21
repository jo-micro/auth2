package ilogger

import (
	"fmt"
	"os"
	"runtime"

	microLogrus "github.com/go-micro/plugins/v4/logger/logrus"
	microLogger "go-micro.dev/v4/logger"
	"jochum.dev/jo-micro/auth2/shared/sutil"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var myLogger *logrus.Logger = nil
var initialized = false

func AppendFlags(flags []cli.Flag) []cli.Flag {
	return sutil.AppendFlag(flags, &cli.StringFlag{
		Name:    "auth2_loglevel",
		Value:   "info",
		Usage:   "Logrus log level default 'info', {panic,fatal,error,warn,info,debug,trace} available",
		EnvVars: []string{"MICRO_AUTH2_LOG_LEVEL"},
	})
}

func Intialized() bool {
	return initialized
}

// caller returns string presentation of log caller which is formatted as
// `/path/to/file.go:line_number`. e.g. `/internal/app/api.go:25`
func caller() func(*runtime.Frame) (function string, file string) {
	return func(f *runtime.Frame) (function string, file string) {
		return "", fmt.Sprintf("%s:%d", f.File, f.Line)
	}
}

func Start(cli *cli.Context) error {
	if initialized {
		return nil
	}

	lvl, err := logrus.ParseLevel(cli.String("auth2_loglevel"))
	if err != nil {
		return err
	}

	myLogger = logrus.New()
	myLogger.Out = os.Stdout
	myLogger.Level = lvl

	myLogger.SetReportCaller(true)

	myLogger.SetFormatter(&logrus.JSONFormatter{
		CallerPrettyfier: caller(),
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyFile: "caller",
		},
	})

	microLogger.DefaultLogger = microLogrus.NewLogger(microLogrus.WithLogger(myLogger))

	initialized = true
	return nil
}

func Stop() error {
	initialized = false
	myLogger = nil

	return nil
}

func Logrus() *logrus.Logger {
	return myLogger
}
