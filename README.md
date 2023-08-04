```
  ______             __       __                     
 /      \           |  \     /  \                    
|  $$$$$$\  ______  | $$\   /  $$  ______    ______  
| $$ __\$$ /      \ | $$$\ /  $$$ |      \  /      \ 
| $$|    \|  $$$$$$\| $$$$\  $$$$  \$$$$$$\|  $$$$$$\
| $$ \$$$$| $$  | $$| $$\$$ $$ $$ /      $$| $$  | $$
| $$__| $$| $$__/ $$| $$ \$$$| $$|  $$$$$$$| $$__/ $$
 \$$    $$ \$$    $$| $$  \$ | $$ \$$    $$| $$    $$
  \$$$$$$   \$$$$$$  \$$      \$$  \$$$$$$$| $$$$$$$ 
                                           | $$    
                                           | $$    
                                            \$$
```


GoMap is a command-line tool written in Golang that allows you to perform TCP connect and TCP SYN scans on one or more hosts. It is inspired by the functionality of Nmap but is focused on simplicity and efficiency.
Installation

To run GoMap, ensure you have Golang installed on your system. Clone this repository and then either use go run or build it as a binary.

### To run using go run:
```
$ go run . -i <ip(s)> -p <port(s)>
```

In default TCP connect mode, GoMap will scan the specified IP(s) and port(s). If -p is not included, the scan will default to the top 1000 ports. Please note that if you use CIDR notation for IP addresses, only one argument can be accepted by the -i flag.

### To run using the binary:
```
$ go build (or go install)
```

After building the binary, you can run GoMap with the same flags as before.

### Example Usage

```
$ GoMap -h
  ______             __       __                     
 /      \           |  \     /  \                    
|  $$$$$$\  ______  | $$\   /  $$  ______    ______  
| $$ __\$$ /      \ | $$$\ /  $$$ |      \  /      \ 
| $$|    \|  $$$$$$\| $$$$\  $$$$  \$$$$$$\|  $$$$$$\
| $$ \$$$$| $$  | $$| $$\$$ $$ $$ /      $$| $$  | $$
| $$__| $$| $$__/ $$| $$ \$$$| $$|  $$$$$$$| $$__/ $$
 \$$    $$ \$$    $$| $$  \$ | $$ \$$    $$| $$    $$
  \$$$$$$   \$$$$$$  \$$      \$$  \$$$$$$$| $$$$$$$ 
                                           | $$    
                                           | $$    
                                            \$$

Starting GoMap...
Usage of GoMap:
  -i string
    	Specify ip(s) you wish to scan (comma delimited without spaces, CiDR notation accepted). Default is localhost. (default "127.0.0.1")
  -p string
    	Specify ports you wish to scan (comma delimited with or without ranges and no spaces). Default is top 1000 most common TCP ports (Warning, this may take a while to run so go do something else). (default "default")
  -s	Scan using TCP SYN mode.
```

#### TCP Connect Scan:
```
$ GoMap -i 192.168.1.69,192.168.1.254 -p 22,80,443
Starting GoMap...

Host 192.168.1.69:
|--port 22---open
|--port 80---open
|--port 443---closed


Host 192.168.1.254:
|--port 22---closed
|--port 80---open
|--port 443---open
```
#### TCP SYN Scan:

For TCP SYN scanning, root privileges are required. Use sudo to execute the binary with elevated privileges.

```
$ sudo GoMap -i 192.168.1.69,192.168.1.85 -p 22-30,443,80 -s
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

### Notes

- GoMap is a simple alternative to Nmap for basic TCP scanning needs.
- In default mode, GoMap performs TCP connect scans.
- For TCP SYN scanning, use the -s flag, and remember to run it with sudo.
- If using CIDR notation, only one argument can be accepted by the -i flag.
- The output formatting for CIDR input might not be optimal.
- If consecutive ports are closed, then this will be represented by:
```
...
|--port 70---open
|--port 79---closed
|............closed
|--port 85---closed
...
```
### Contribution

Feel free to contribute to GoMap by opening issues or submitting pull requests on the GitHub repository.

### License

This project is licensed under GPL 3.0. See the LICENSE file for details.
