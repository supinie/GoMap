package main

import (
	"flag"
	"fmt"
)

func main() {
	// declare vars
	var ip string
	var port string
	var mode bool

	fmt.Println("Starting GoMap...\n")

	flag.StringVar(&ip, "i", "127.0.0.1", "Specify ip(s) you wish to scan. Default is localhost.")
	flag.StringVar(&port, "p", "default", "Specify ports you wish to scan (comma delimited with or without ranges). Default is top 1000 most common TCP ports.")
	flag.BoolVar(&mode, "m", false, "Specify the mode you wish to scan with, 0 is TCP connect (default) and 1 is TCP SYN")

	flag.Parse()

	fmt.Println(ip, port, mode)
}
