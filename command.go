package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	packagecloud "github.com/atotto/packagecloud/api/v1"
	"github.com/google/subcommands"
)

type commandBase struct {
	name         string
	synopsis     string
	usage        string
	examples     []string
	setFlagsFunc func(f *flag.FlagSet)
	executeFunc  func(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus
}

func (c *commandBase) Name() string { return c.name }
func (c *commandBase) Synopsis() string {
	return fmt.Sprintf("packagecloud %s", c.synopsis)
}

func (c *commandBase) Usage() string {
	w := bytes.NewBufferString(c.usage)
	fmt.Fprintln(w)
	if len(c.examples) > 0 {
		fmt.Fprintln(w, "\nexample:")
		for _, ex := range c.examples {
			fmt.Fprintf(w, "    %s\n", ex)
		}
	}
	return w.String()
}

func (c *commandBase) SetFlags(f *flag.FlagSet) {
	if c.setFlagsFunc == nil {
		return
	}
	c.setFlagsFunc(f)
}

func (c *commandBase) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	return c.executeFunc(ctx, f, args)
}

var pushPackageCommand = &commandBase{
	"push",
	"pushing a package",
	"push name/repo/distro/version filepath",
	[]string{"packagecloud push example-user/example-repository/ubuntu/xenial /tmp/example.deb"},
	nil,
	func(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
		repos, distro, version, ok := splitPackageTarget(f.Arg(0))
		if !ok {
			return subcommands.ExitUsageError
		}
		fpath := f.Arg(1)
		if err := packagecloud.PushPackage(ctx, repos, distro, version, fpath); err != nil {
			log.Println(err)
			return subcommands.ExitFailure
		}

		return subcommands.ExitSuccess
	},
}

var deletePackageCommand = &commandBase{
	"yank",
	"deleting a package",
	"yank name/repo/distro/version filepath",
	[]string{"packagecloud yank example-user/example-repository/ubuntu/xenial example_1.0.1-1_amd64.deb"},
	nil,
	func(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
		repos, distro, version, ok := splitPackageTarget(f.Arg(0))
		if !ok {
			return subcommands.ExitUsageError
		}
		fpath := f.Arg(1)
		if err := packagecloud.DeletePackage(ctx, repos, distro, version, fpath); err != nil {
			log.Println(err)
			return subcommands.ExitFailure
		}

		return subcommands.ExitSuccess
	},
}

var promotePackageCommand = &commandBase{
	"promote",
	"promote package",
	"promote name/src_repo/distro/version filepath name/dst_repo",
	[]string{"packagecloud promote example-user/repo1/ubuntu/xenial example_1.0-1_amd64.deb example-user/repo2"},
	nil,
	func(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
		srcRepos, distro, version, ok := splitPackageTarget(f.Arg(0))
		if !ok {
			return subcommands.ExitUsageError
		}
		fpath := f.Arg(1)
		dstRepos := f.Arg(2)
		if err := packagecloud.PromotePackage(ctx, dstRepos, srcRepos, distro, version, fpath); err != nil {
			log.Println(err)
			return subcommands.ExitFailure
		}

		return subcommands.ExitSuccess
	},
}

func splitPackageTarget(target string) (repos, distro, version string, ok bool) {
	ss := strings.SplitN(target, "/", 4)
	if len(ss) != 4 {
		ok = false
		return
	}
	repos = fmt.Sprintf("%s/%s", ss[0], ss[1])
	distro = ss[2]
	version = ss[3]
	ok = true
	return
}
