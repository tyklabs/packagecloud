# packagecloud

A CLI for packagecloud, written in Go. Forked from [github.com/atotto/packagecloud](https://github.com/atotto/packagecloud) with some bugfixes and explicit verification that pushes succeeded.

## Install

### CLI
```
go install github.com/tyklabs/packagecloud
```

### Dependency
```
go get -u github.com/tyklabs/packagecloud
```

## Usage

### Pushing a package

    packagecloud push example-user/example-repository/ubuntu/xenial /tmp/example.deb
    
### Deleting a package

    packagecloud rm example-user/example-repository/ubuntu/xenial example_1.0.1-1_amd64.deb

### Promoting packages between repositories

    packagecloud promote example-user/repo1/ubuntu/xenial example_1.0-1_amd64.deb example-user/repo2
