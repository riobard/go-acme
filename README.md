# go-acme

Automated Certificate Management Environment (ACME) client written in Go using
just standard library. No external dependencies required.

## Features

- Authorizing multiple domain names in parallel.
- Generate certificates from separate hosts holding the account key.


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

Then test the config and restart Nginx

```sh
nginx -t
nginx -s reload
```


If you want to run `go-acme` on the same host with the server, you can simply
run

```sh
acme -genrsa 4096 > account.key
acme -addr 127.0.0.1:81 -key account.key -domains example.com,www.example.com > chain.pem
```

and wait for the domain key, domain certifcate, and issuer certificate to be put
into `chain.pem` file.


If you want to run `go-acme` on another host, you need to use SSH to forward
requests to port 81 on the server to the one running `go-acme`.

```sh
ssh -N -T -R 81:127.0.0.1:8181 server-hostname
```

Then you run

```sh
acme -genrsa 4096 > account.key
acme -addr 127.0.0.1:8181 -key account.key -domains example.com,www.example.com > chain.pem
```

After that you need to copy `chain.pem` file back to the server.




## TODO

- Certificate revokation
