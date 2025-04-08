package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/subcommands"
	"github.com/mattn/go-zglob"
	packagecloud "github.com/tyklabs/packagecloud/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type commandBase struct {
	name         string
	synopsis     string
	usage        string
	examples     []string
	setFlagsFunc func(f *flag.FlagSet)
	executeFunc  func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus
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

func (c *commandBase) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	return c.executeFunc(ctx, f, args)
}

var pushPackageCommandVerifyExist bool
var pushPackageCommand = &commandBase{
	"push",
	"push a package",
	"push [-verify] name/repo/distro/version filepath",
	[]string{"packagecloud push example-user/example-repository/ubuntu/xenial /tmp/example.deb"},
	func(f *flag.FlagSet) {
		f.BoolVar(&pushPackageCommandVerifyExist, "verify", false, "Verify whether packages were successfully uploaded to pakcagecloud - compares md5sum of file on disk and on remote")

	},
	func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
		repos, distro, version, n := splitPackageTarget(f.Arg(0))
		if n < 3 {
			return subcommands.ExitUsageError
		}

		var files []string
		for _, file := range f.Args()[1:] {
			fs, err := zglob.Glob(file)
			if err != nil {
				return subcommands.ExitFailure
			}
			files = append(files, fs...)
		}
		fmt.Printf("pushing %d files...\n", len(files))

		for _, file := range files {
			_, fname := filepath.Split(file)
			log.Printf("push: %s", fname)
			details, err := packagecloud.PushPackage(ctx, repos, distro, version, file)
			if err != nil {
				if status.Code(err) == codes.AlreadyExists {
					log.Printf("%s already exist", fname)
					continue
				}
				log.Printf("%s %s", fname, err)
				return subcommands.ExitFailure
			}
			// Retrieve the package details provided by packagecloud and verify md5sum to that from
			// the file on disk
			if pushPackageCommandVerifyExist {
				verified, err := verifyPackagePush(details, file)
				if err != nil {
					log.Printf("Error verifying push: %s(%s/%s): %v", file, distro, version, err)
					return subcommands.ExitFailure
				}
				if !verified {
					log.Printf("md5sum verification failed for package on remote: %s(%s/%s)", file, distro, version)
					return subcommands.ExitFailure
				}
			}
		}

		return subcommands.ExitSuccess
	},
}

var searchPackageCommand = &commandBase{
	"list",
	"list package",
	"list name/repo query [version]",
	[]string{"packagecloud list example-user/example-repository example 1.0.0"},
	nil,
	func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
		repos, distro, _, n := splitPackageTarget(f.Arg(0))
		if n < 2 {
			return subcommands.ExitUsageError
		}
		query := f.Arg(1)
		details, err := packagecloud.SearchPackage(ctx, repos, distro, 0, query, "")
		if err != nil {
			log.Println(err)
			return subcommands.ExitFailure
		}
		version := f.Arg(2)
		for _, detail := range details {
			if version == "" || detail.Version == version {
				fmt.Printf("%s %s %s %s\n", detail.DistroVersion, detail.Filename, detail.Name, detail.Version)
			}
		}

		return subcommands.ExitSuccess
	},
}

var pullPackageCommand = &commandBase{
	"pull",
	"pull package",
	"pull name/repo[/distro/version] filename",
	[]string{"packagecloud pull example-user/example-repository example_1.0.0_all.deb"},
	nil,
	func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
		repos, distro, version, n := splitPackageTarget(f.Arg(0))
		if n < 2 {
			return subcommands.ExitUsageError
		}
		query := f.Arg(1)
		details, err := packagecloud.SearchPackage(ctx, repos, distro, 0, query, "")
		if err != nil {
			log.Println(err)
			return subcommands.ExitFailure
		}
		for _, detail := range details {
			if version == "" || detail.Version == version {
				fmt.Printf("%s %s %s %s\n", detail.Filename, detail.Name, detail.Version, detail.DistroVersion)
				f, err := os.OpenFile(detail.Filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
				if err != nil {
					log.Println(err)
					return subcommands.ExitFailure
				}
				defer f.Close()
				resp, err := http.Get(detail.DownloadURL)
				if err != nil {
					log.Println(err)
					return subcommands.ExitFailure
				}
				defer resp.Body.Close()
				io.Copy(f, resp.Body)
			}
		}

		return subcommands.ExitSuccess
	},
}

var deletePackageCommand = &commandBase{
	"rm",
	"delete a package",
	"rm name/repo/distro/version filepath",
	[]string{"packagecloud rm example-user/example-repository/ubuntu/xenial example_1.0.1-1_amd64.deb"},
	nil,
	func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
		repos, distro, version, n := splitPackageTarget(f.Arg(0))
		if n != 4 {
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

var deleteVersionCommand = &commandBase{
	"rmv",
	"remove a package version",
	"rmv name/repo version",
	[]string{"packagecloud rmv example-user/example-repository 1.0.0"},
	nil,
	func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
		repos, distro, _, n := splitPackageTarget(f.Arg(0))
		if n < 2 {
			return subcommands.ExitUsageError
		}
		version := f.Arg(1)
		details, err := packagecloud.SearchPackage(ctx, repos, distro, 0, version, "")
		if err != nil {
			log.Println(err)
			return subcommands.ExitFailure
		}
		for _, detail := range details {
			if detail.Version == version {
				fmt.Printf("deleting %s %s %s %s\n", detail.DistroVersion, detail.Filename, detail.Name, detail.Version)
				err := packagecloud.DeleteURL(ctx, "https://packagecloud.io"+detail.DestroyURL)
				if err != nil {
					log.Println(err)
				}
			}
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
	func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
		srcRepos, distro, version, n := splitPackageTarget(f.Arg(0))
		if n != 4 {
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

var promoteVersionDryRun bool
var promoteVersionPackageCommand = &commandBase{
	"promoteversion",
	"promote all packages having the given version",
	"promote name/src_repo version name/dst_repo",
	[]string{"packagecloud promoteversion example-user/repo-unstable  1.0.0 example-user/repo-stable"},
	func(f *flag.FlagSet) {
		f.BoolVar(&promoteVersionDryRun, "dryrun", false, "Do not actually promote, just list the ones that will be promoted")

	},
	func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
		if len(f.Args()) != 3 {
			return subcommands.ExitUsageError
		}
		srcRepo := f.Arg(0)
		version := f.Arg(1)
		dstRepo := f.Arg(2)
		if srcRepo == "" || version == "" || dstRepo == "" {
			return subcommands.ExitUsageError
		}
		if promoteVersionDryRun {
			log.Printf("Dry run: Won't actually do any promotion")
		}
		debPkgs, err := packagecloud.SearchPackage(ctx, srcRepo, "", 250, version, "deb")
		if err != nil {
			log.Printf("Error getting deb packages info: %s->%s: %v", srcRepo, dstRepo, err)
		}
		var promoteList []packagecloud.PackageDetail

		for _, deb := range debPkgs {
			if deb.Version == version {
				promoteList = append(promoteList, deb)
			}
		}
		rpmPkgs, err := packagecloud.SearchPackage(ctx, srcRepo, "", 250, version, "rpm")
		if err != nil {
			log.Printf("Error getting rpm packages info: %s->%s: %v", srcRepo, dstRepo, err)
		}
		for _, rpm := range rpmPkgs {
			if rpm.Version == version {
				promoteList = append(promoteList, rpm)
			}
		}
		if len(promoteList) == 0 {
			log.Printf("No packages to promote")
			return subcommands.ExitFailure
		}
		log.Println("Promoting packages..")
		summaryDistro := make(map[string][]string)
		var summaryArch []string
		var num int
		var pkg packagecloud.PackageDetail
		for num, pkg = range promoteList {
			distro := strings.Split(pkg.DistroVersion, "/")
			info, err := packagecloud.ShowPackage(ctx, pkg.PackageURL)
			if err != nil {
				log.Println(err)
				return subcommands.ExitFailure
			}
			if !promoteVersionDryRun {
				if err := packagecloud.PromotePackage(ctx, dstRepo, srcRepo, distro[0], distro[1], pkg.Filename); err != nil {
					log.Println(err)
					return subcommands.ExitFailure
				}
			} else {
				log.Printf("Promoting package %s(%s/%s) from %s->%s", pkg.Filename, distro[0], distro[1], srcRepo, dstRepo)
			}
			summaryDistro[pkg.Type] = append(summaryDistro[pkg.Type], info.DistroVersion)
			summaryArch = append(summaryArch, info.Arch)
		}
		// display a nice summary about the promotion
		fmt.Printf("%d packages having %s architectures for %s were promoted from %s to %s\n", num+1, strings.Join(uniqueSummary(summaryArch), ","), version, srcRepo, dstRepo)
		fmt.Printf("Debian based distro versions: %s\n", strings.Join(uniqueSummary(summaryDistro["deb"]), ","))
		fmt.Printf("RPM based distro versions: %s\n", strings.Join(uniqueSummary(summaryDistro["rpm"]), ","))
		return subcommands.ExitSuccess
	},
}

var publishPackageCommandDebvers string
var publishPackageCommandRpmvers string
var publishPackageCommandDryRun bool
var publishPackageCommand = &commandBase{
	"publish",
	"publish a deb/rpm package across multiple distro versions, " +
		"please provide --debversions or --rpmversions accordingly",
	`publish [--rpmvers  "distro/ver1 distro/ver2..."] [--debvers "distro/ver1 distro/ver2"...]  name/repo filepath`,
	[]string{`push a deb package to ubuntu/jammy, debian/bookworm and debian/bullseye:
	packagecloud publish --debvers "ubuntu/jammy debian/bookworm debian/bullseye" jake/jake-stable jake.deb`,
		`push an rpm package to el/7 el/8 and el/9:
	packagecloud publish --rpmvers "el/7 el/8 el/9" jake/jake-stable jake.rpm`},
	func(f *flag.FlagSet) {
		f.StringVar(&publishPackageCommandDebvers, "debvers", "", "Debian versions to publish this package to")
		f.StringVar(&publishPackageCommandRpmvers, "rpmvers", "", "RPM versions to publish this package to")
		f.BoolVar(&publishPackageCommandDryRun, "dryrun", false, "Do not publish, only show logs on what will be done")
	},
	func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
		retStatus := subcommands.ExitSuccess
		repo := f.Arg(0)
		fileName := f.Arg(1)
		dryRun := publishPackageCommandDryRun
		// Retry this many times in case of failed verification post push
		maxRetries := 2
		var publishVersions []string
		if filepath.Ext(fileName) == ".deb" && publishPackageCommandDebvers != "" {
			publishVersions = strings.Fields(publishPackageCommandDebvers)
			log.Printf("Publishing to repo %s, the file %s for debian versions: %s", repo, fileName, publishVersions)

		} else if filepath.Ext(fileName) == ".rpm" && publishPackageCommandRpmvers != "" {
			publishVersions = strings.Fields(publishPackageCommandRpmvers)
			log.Printf("Publishing to repo %s, the file %s for rpm versions: %s", repo, fileName, publishVersions)

		} else {
			log.Println("Not a .deb/rpm file or no appropriate --debvers/--rpmvers given, exiting..")
			// Exit with success to avoid goreleaser complaining on binary files.
			return subcommands.ExitSuccess
		}
		retryCount := 1
		for i := 0; i < len(publishVersions); i++ {
			var err error
			var details packagecloud.PackageDetail
			distro := publishVersions[i]
			dv := strings.Split(distro, "/")
			log.Printf("Pushing file %s for version: %s", fileName, distro)
			if !dryRun {
				details, err = packagecloud.PushPackage(ctx, repo, dv[0], dv[1], fileName)
			}
			if err != nil && status.Code(err) != codes.AlreadyExists {
				log.Printf("Error pushing package %s for %s: %v", fileName, distro, err)
				retStatus = subcommands.ExitFailure
				continue
			} else if status.Code(err) == codes.AlreadyExists { /* Package exists already - overwrite(yank & push) and rerun this iteration */
				log.Printf("Package exists already, we'll overwrite(yank and then push again: %s(%s)", fileName, distro)
				err := packagecloud.DeletePackage(ctx, repo, dv[0], dv[1], fileName)
				if err != nil {
					log.Printf("Error yanking package: %s (%s): %v", fileName, distro, err)
					retStatus = subcommands.ExitFailure
					continue
				}
				// Rerun this iteration.
				i--
				continue
			}
			// Verify if package is pushed to remote, rerun this push if not verified
			verified, err := verifyPackagePush(details, fileName)
			if err != nil {
				log.Printf("Can not verify pushed package on remote: %s(%s): %v", fileName, distro, err)
				retStatus = subcommands.ExitFailure
				continue
			}
			if !verified && (retryCount <= maxRetries) {
				log.Printf("Verification failed for %s(%s), will retry push, attempt #%d", fileName, distro, retryCount)
				retryCount++
				i--
				continue
			} else if retryCount > maxRetries {
				log.Printf("Exceeded push retries for %s(%s)", fileName, distro)
				retStatus = subcommands.ExitFailure
				retryCount = 1
				continue
			}

		}
		return retStatus
	},
}

// Retrieve the package details provided by packagecloud and verify md5sum to that from
// the file on disk
func verifyPackagePush(detail packagecloud.PackageDetail, fileName string) (bool, error) {
	fd, err := os.OpenFile(fileName, os.O_RDONLY, 044)
	if err != nil {
		log.Printf("Error opening file: %s: %v", fileName, err)
		return false, err
	}
	defer fd.Close()
	h := md5.New()
	_, err = io.Copy(h, fd)
	if err != nil {
		log.Printf("I/O error: calculating md5sum: %s: %v", fileName, err)
		return false, err
	}
	md5Sum := hex.EncodeToString(h.Sum(nil))
	log.Printf("md5sum of file on disk: %s, on pc remote: %s", md5Sum, detail.Md5Sum)
	if detail.Md5Sum != md5Sum {
		log.Printf("File checksums different: on disk: %s, on packagecloud: %s", md5Sum, detail.Md5Sum)
		return false, nil
	}
	return true, nil
}

func splitPackageTarget(target string) (repos, distro, version string, n int) {
	ss := strings.SplitN(target, "/", 4)
	n = len(ss)
	if n >= 2 {
		repos = fmt.Sprintf("%s/%s", ss[0], ss[1])
	}
	if n >= 3 {
		distro = ss[2]
	}
	if n >= 4 {
		version = ss[3]
	}
	return
}

// uniqueSummary takes a slice having package promotion summary list(slice)
// and returns a slice with unique elements after removing any similiar entries
func uniqueSummary(in []string) []string {
	var u []string
	t := make(map[string]bool)
	for _, v := range in {
		switch v {
		case "aarch64":
			v = "arm64"
		case "x86_64":
			v = "amd64"
		}
		if _, ok := t[v]; !ok {
			t[v] = true
			u = append(u, v)
		}
	}
	return u
}

var helpDistroCommand = &commandBase{
	"distro",
	"list supported distributions",
	"distro [deb/py]",
	[]string{"packagecloud distro", "packagecloud distro deb", "packagecloud distro deb ubuntu", "packagecloud distro | jq .deb"},
	nil,
	func(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
		var v any
		distributions, err := packagecloud.GetDistributions(ctx)
		if err != nil {
			log.Println(err)
			return subcommands.ExitUsageError
		}
		switch typ := f.Arg(0); typ {
		case "deb", "debian":
			if name := f.Arg(1); name != "" {
				for _, distros := range distributions.Deb {
					if distros.IndexName == name {
						v = distros.Versions
						break
					}
				}
			} else {
				v = distributions.Deb
			}

		case "py", "python":
			v = distributions.Py
		case "":
			v = distributions
		default:
			log.Printf("not supported type:%s", typ)
			return subcommands.ExitUsageError
		}
		if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
			return subcommands.ExitFailure
		}
		return subcommands.ExitSuccess
	},
}
