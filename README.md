# GoMap

to run:
`go run . -i <ip(s)> -p <port(s)>` in default TCP connect mode, `go run . -i <ip(s)> -p <port(s)> -s` to run in TCP SYN mode.

or build as a binary:
`go build` (or `go install` to use in any directory)
then run as usual binary with same flags as before

Example:
```
$ ./GoMap.exe -i 192.168.1.69,192.168.1.254 -p 22,80,443
Starting GoMap...

Host 192.168.1.69:
|--port 22 --- open
|--port 80 --- open
|--port 443 --- closed


Host 192.168.1.254:
|--port 22 --- closed
|--port 80 --- open
|--port 443 --- open

```

