# Mole

Mole creates publicly accessible HTTP/HTTPS/TCP/UDP tunnels for local development.
Tunnels are implemented using ssh remote port forwarding. Subdomains are assigned
using an auto-incrementing id for every forwarding request.

## Installation

Install the mole server. You will need go and openssh installed before preceeding.

```bash
go get -u github.com/michalnicp/mole
```

Generate the ssh host key file.

```bash
ssh-keygen -t rsa -b 2048 -f /etc/mole/ssh_host_key
```

Start mole.

```bash
$ mole
mole version 0.0.0
```

## Configuration

Mole is configured using environment variables

| Variable              | Default           | Description                                 |
|-----------------------|-------------------|---------------------------------------------|
| `SERVER_NAME`         |                   | The fully qualified domain name (hostname). |
| `HTTP_ADDR`           | `:8080`           | The http server address to listen on.       |
| `SSH_ADDR`            | `:2022`           | The ssh server address to listen on.        |
| `SSH_HOST_KEY_PATH`   | `ssh_host_key`    | The path to the ssh server host key file.   |
| `SSH_AUTHORIZED_KEYS` | `authorized_keys` | The path to the authorized keys file.       |

## Quickstart

This quickstart assumes that the `mole` server is running and available at `example.com`.
You can use any ssh client that supports remote forwarding. For example, using `openssh`

```bash
$ ssh example.com -p 2022 -R 8000:localhost:8000
mole version 0.0.0
forwarding http://1.example.com->localhost:8000
```

Test using `ncat`. The following will start `ncat` listening on port `8000`

```bash
$ printf 'HTTP/1.1 200 OK\r\n' | ncat -l 8000
```

Then, in another terminal, make an http request using `curl`

```bash
$ curl 1.example.com
```

You should see the following output from `ncat`

```bash
$ printf 'HTTP/1.1 200 OK\r\n' | ncat -l 8000
GET / HTTP/1.1
Host: 1.example.com
User-Agent: curl/7.68.0
Accept: */*

```
