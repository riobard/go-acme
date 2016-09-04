# go-acme

Automated Certificate Management Environment (ACME) client written in Go using
just standard library. No external dependencies required.

## Features

- Authorizing domain names in parallel to greatly speed up the
    issuance of multi-domain SAN certificates.
- Generate certificates from another host holding your account key. There is no
    need to keep the account key on the public facing server.
- Single binary for easy deployment. Just drop and run.


## Usage

The workflow of `go-acme` is very simple:

1. Setup Nginx to reverse proxy ACME HTTP challenges.
2. Launch `go-acme` to authorize domain names and generate certificates.
3. Done.


Add the following section to `server` section of your nginx config. It will
forward requests for ACME HTTP challenges to a server listening on port 81. You
can use any port number, but it is recommended that you use a privileged port so
that only root can bind to for security reasons.

```nginx
location ^~ /.well-known/acme-challenge/ {
    proxy_pass http://127.0.0.1:81;
}
```

Then restart Nginx

```sh
nginx -s reload
```

Generate a 4096-bit RSA account key if you do not have one yet

```sh
acme -genrsa 4096 > account.key
```

Generate a 2048-bit RSA certificate key if you do not have one yet

```sh
acme -genrsa 2048 > cert.key
```

To run `go-acme` on the same host with the server, execute

```sh
acme -addr 127.0.0.1:81 -acckey account.key -crtkey cert.key -domains example.com,www.example.com > cert.pem
```

and wait for your domain certifcate and issuer certificate to be put into `cert.pem` file.


Alternatively, you can run `go-acme` on another host. This has the benefit that
there is no need to put the private account key on the public-facing web server.

To do so, you need to use SSH to forward port 81 on the server to a free port
(8181 in the example below) on the host running `go-acme`.

```sh
ssh -N -T -R 81:127.0.0.1:8181 server-hostname
```

and then run `go-acme` listening on the forwarded port (8181)

```sh
acme -addr 127.0.0.1:8181 -acckey account.key -crtkey cert.key -domains example.com,www.example.com > cert.pem
```

After that you need to copy `cert.key` and `cert.pem` files back to the web server.




## TODO

- Certificate revokation
