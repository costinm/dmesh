# Gomobile

Initially the code was using 'exec' on an linux/arm binary, communicating
with UDS. Now it's using gomobile bindings to create an .aar file.

An interesting approach allowing JNI access:
https://github.com/xlab/android-go/tree/master/android


# Build tools

We want to have all the deps in a docker container, for reproductible and fast builds.

'xgo' seems the right approach - but the main repo is out of date/unmanaintained.

Looking at various forks:

https://github.com/mysteriumnetwork/xgomobile documents the raw command, and adds gomobile - but 
still go 1.13

```shell

docker run --rm \
    -v "$PWD"/build:/build \
    -v "$GOPATH"/.xgo-cache:/deps-cache:ro \
    -v "$PWD"/src:/ext-go/1/src:ro \
    -e OUT=Mysterium \
    -e FLAG_V=false \
    -e FLAG_X=false \
    -e FLAG_RACE=false \
    -e FLAG_BUILDMODE=default \
    -e TARGETS=android/. \
    -e EXT_GOPATH=/ext-go/1 \
    -e GO111MODULE=off \
    mysteriumnetwork/xgomobile:1.13.6 mobilepkg
    
```

techknowlogick/xgo:latest - removes android

https://github.com/vegaprotocol/xgo is up-to-date, 

```shell

#   REPO_REMOTE    - Optional VCS remote if not the primary repository is needed
#   REPO_BRANCH    - Optional VCS branch to use, if not the master branch
#   DEPS           - Optional list of C dependency packages to build
#   ARGS           - Optional arguments to pass to C dependency configure scripts
#   PACK           - Optional sub-package, if not the import path is being built
#   OUT            - Optional output prefix to override the package name
#   FLAG_V         - Optional verbosity flag to set on the Go builder
#   FLAG_X         - Optional flag to print the build progress commands
#   FLAG_RACE      - Optional race flag to set on the Go builder
#   FLAG_TAGS      - Optional tag flag to set on the Go builder
#   FLAG_LDFLAGS   - Optional ldflags flag to set on the Go builder
#   FLAG_BUILDMODE - Optional buildmode flag to set on the Go builder
#   TARGETS        - Comma separated list of build targets to compile for
#   GO_VERSION     - Bootstrapped version of Go to disable uncupported targets
#   EXT_GOPATH     - GOPATH elements mounted from the host filesystem

args := []string{
		"run", "--rm",
		"-v", folder + ":/build",
		"-v", depsCache + ":/deps-cache:ro",
		"-e", "REPO_REMOTE=" + config.Remote,
		"-e", "REPO_BRANCH=" + config.Branch,
		"-e", "PACK=" + config.Package,
		"-e", "DEPS=" + config.Dependencies,
		"-e", "ARGS=" + config.Arguments,
		"-e", "OUT=" + config.Prefix,
		"-e", "TARGETS=" + strings.Replace(strings.Join(config.Targets, " "), "*", ".", -1),
	}
	for i := 0; i < len(locals); i++ {
		args = append(args, []string{"-v", fmt.Sprintf("%s:%s:ro", locals[i], mounts[i])}...)
	}
	args = append(args, []string{"-e", "EXT_GOPATH=" + strings.Join(paths, ":")}...)

	args = append(args, []string{image, config.Repository}...)
```

- Cross deps are cached to a mounted dir (volume).
- local builds: 
    - GOPATH used to find current dir
    - 
