[![Build Status](https://drone.fk.jochum.dev/api/badges/jo-micro/auth2/status.svg)](https://drone.fk.jochum.dev/jo-micro/auth2) [![Go Reference](https://pkg.go.dev/badge/jochum.dev/jo-micro/auth2.svg)](https://pkg.go.dev/jochum.dev/jo-micro/auth2)

# auth2

An auth provider for go-micro, it get's users from a postgres database, in the future maybe from other SQL Databases supported by [bun](https://bun.uptrace.dev/) as well.

It registers itself with [router](https://jochum.dev/jo-micro/router), if you use it in your stack.

## JWT Token Auth

### Generate keys

```bash
task keys
```

## Developers corner

### Build podman/docker image

#### Prerequesits

- podman
- [Task](https://taskfile.dev/#/installation)

#### Build

```bash
task
```

#### Remove everything

```bash
task rm
```

## Authors

- René Jochum - rene@jochum.dev

## License

Its dual licensed:

- Apache-2.0
- GPL-2.0-or-later
