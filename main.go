package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/subcommands"
	packagecloud "github.com/tyklabs/packagecloud/api/v1"
)

var (
	PACKAGECLOUD_TOKEN = os.Getenv("PACKAGECLOUD_TOKEN")
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	ctx, cancel := context.WithCancel(context.Background())

	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(pushPackageCommand, "package")
	subcommands.Register(pullPackageCommand, "package")
	subcommands.Register(searchPackageCommand, "package")
	subcommands.Register(promotePackageCommand, "package")
	subcommands.Register(deletePackageCommand, "package")
	subcommands.Register(deleteVersionCommand, "package")
	subcommands.Register(helpDistroCommand, "help")
	subcommands.Register(promoteVersionPackageCommand, "package")
	subcommands.Register(publishPackageCommand, "package")

	flag.Parse()

	if PACKAGECLOUD_TOKEN == "" {
		fmt.Fprintf(flag.CommandLine.Output(), `
Please set an environment variable with the name PACKAGECLOUD_TOKEN, containing the value of a packagecloud API token.
You can find a packagecloud API token at https://packagecloud.io/api_token .
`)
		log.Println(`PACKAGECLOUD_TOKEN is empty`)
		os.Exit(2)
	}
	ctx = packagecloud.WithPackagecloudToken(ctx, PACKAGECLOUD_TOKEN)

	go func() {
		os.Exit(int(subcommands.Execute(ctx)))
	}()

	select {
	case <-sig:
		cancel()
	case <-ctx.Done():
	}
}
