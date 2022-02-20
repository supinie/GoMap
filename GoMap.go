package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func connect(ip string, port int, reply chan string) bool {
	host := ip + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", host, 60*time.Second)

	if err != nil {
		reply <- "|--port " + strconv.Itoa(port) + " --- closed"
		return false
	}
	defer conn.Close()
	reply <- "|--port " + strconv.Itoa(port) + " --- open"
	return true
}

// func SYN(ip string, port int) {

// }

func main() {
	// declare vars
	var ip string
	var port = "default"
	var syn bool
	x := make(map[string]string)

	fmt.Println("Starting GoMap...")

	flag.StringVar(&ip, "i", "127.0.0.1", "Specify ip(s) you wish to scan (comma delimited without spaces, CiDR notation accepted). Default is localhost.")
	flag.StringVar(&port, "p", "default", "Specify ports you wish to scan (comma delimited with or without ranges and no spaces). Default is top 1000 most common TCP ports.")
	flag.BoolVar(&syn, "s", false, "Scan using TCP SYN mode.")

	flag.Parse()

	// put the chosen ports into a map so they can easily be used later.
	ports := strings.Split(port, ",")
	var portList = make(map[int]int)
	for p := 0; p < len(ports); p++ {
		if temp, err := strconv.Atoi(ports[p]); err == nil {
			portList[p] = temp
		}
	}

	// do the same for ips
	ips := strings.Split(ip, ",")
	var ipList = make(map[int]string)
	for i := 0; i < len(ips); i++ {
		ipList[i] = ips[i]
	}

	if syn == false {
		reply := make(chan string)
		for portIndex := 0; portIndex < len(portList); portIndex++ {
			for ipIndex := 0; ipIndex < len(ipList); ipIndex++ {
				go connect(ipList[ipIndex], portList[portIndex], reply)
				x[ipList[ipIndex]] += <-reply + "\n"
			}
		}
	}
	for scanned := range x {
		fmt.Println("\nHost " + scanned + ":")
		fmt.Println(x[scanned])
	}
	// } else {
	// 	SYN(ip, port)
	// }
}
