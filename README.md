# GoMap

# to run:
`go run . -i <ip(s)> -p <port(s)>` in default TCP connect mode, `go run . -i <ip(s)> -p <port(s)> -s` to run in TCP SYN mode (sudo needed). Order of flags does not matter. If `-p` is not included, it will default to top 1000 ports.

*please note, if using CiDR notation, only one argument can be accepted by `-i`, current output for CiDR input is a bit rubbish as well sorry.

# or build as a binary:
`go build` (or `go install`)
then run as usual binary with same flags as before

Example:
```
$ ./GoMap -i 192.168.1.69,192.168.1.254 -p 22,80,443
Starting GoMap...

Host 192.168.1.69:
|--port 22---open
|--port 80---open
|--port 443---closed


Host 192.168.1.254:
|--port 22---closed
|--port 80---open
|--port 443---open


$ sudo ./GoMap -i 192.168.1.69,192.168.1.85 -p 22-30,443,80 -s

Starting GoMap...

Host 192.168.1.69:
|--port 22---open
|--port 23---closed
|............closed
|--port 30---closed
|--port 80---open
|--port 443---closed


Host 192.168.1.85:
|--port 22---open
|--port 23---closed
|............closed
|--port 30---closed
|--port 80---closed
|--port 443---closed

```

