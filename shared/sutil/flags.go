package sutil

import "github.com/urfave/cli/v2"

func AppendFlag(flags []cli.Flag, flag cli.Flag) []cli.Flag {
	has := false
	for _, f := range flags {
		if f.Names()[0] == flag.Names()[0] {
			has = true
			break
		}
	}

	if has {
		return flags
	}

	return append(flags, flag)
}

func AppendFlags(flags []cli.Flag, newFlags ...cli.Flag) []cli.Flag {
	for _, f := range newFlags {
		flags = AppendFlag(flags, f)
	}

	return flags
}
