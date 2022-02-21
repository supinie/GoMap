package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/adedayo/cidr"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func connect(ip string, port int, reply chan string) bool {
	host := ip + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)

	if err != nil {
		reply <- "|--port " + strconv.Itoa(port) + "---closed"
		return false
	}

	defer conn.Close()
	reply <- "|--port " + strconv.Itoa(port) + "---open"
	return true
}

func SYN(ip string, port int, reply chan string) bool {
	dstaddrs, err := net.LookupIP(ip)
	if err != nil {
		log.Fatal(err)
	}

	// parse the destination host and port from the command line os.Args
	dstip := dstaddrs[0].To4()
	var dstport layers.TCPPort
	dstport = layers.TCPPort(port)

	srcip, sport := localIPPort(dstip)
	srcport := layers.TCPPort(sport)

	// Our IP header... not used, but necessary for TCP checksumming.
	ipHeader := &layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ipHeader)

	// Serialize.  Note:  we only serialize the TCP layer, because the
	// socket we get with net.ListenPacket wraps our data in IPv4 packets
	// already.  We do still need the IP layer to compute checksums
	// correctly, though.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		log.Fatal(err)
	}

	// Set deadline so we don't wait forever.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatal(err)
	}

	for {
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			log.Println("error reading packet: ", err)
			return false
		} else if addr.String() == dstip.String() {
			// Decode a packet
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.DstPort == srcport {
					if tcp.SYN && tcp.ACK {
						reply <- "|--port " + strconv.Itoa(port) + "---open"
					} else {
						reply <- "|--port " + strconv.Itoa(port) + "---closed"
					}
					return true
				}
			}
		}
	}
}

func localIPPort(dstip net.IP) (net.IP, int) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		log.Fatal(err)
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port
		}
	}
	return nil, -1
}

func main() {
	// declare vars
	var ip string
	var port = "default"
	var syn bool
	result := make(map[string]string)
	scannedPorts := make(map[int]string)

	fmt.Println("\nStarting GoMap...")

	flag.StringVar(&ip, "i", "127.0.0.1", "Specify ip(s) you wish to scan (comma delimited without spaces, CiDR notation accepted). Default is localhost.")
	flag.StringVar(&port, "p", "default", "Specify ports you wish to scan (comma delimited with or without ranges and no spaces). Default is top 1000 most common TCP ports (Warning, this may take a while to run so go do something else).")
	flag.BoolVar(&syn, "s", false, "Scan using TCP SYN mode.")

	flag.Parse()

	if port == "default" {
		if content, err := ioutil.ReadFile("tcp.txt"); err == nil {
			port = string(content)
		}
	}

	// put the chosen ports into a map so they can easily be used later.
	ports := strings.Split(port, ",")
	for p := 0; p < len(ports); p++ {
		if strings.Contains(ports[p], "-") {
			temporary0, err0 := strconv.Atoi(strings.Split(ports[p], "-")[0])
			temporary1, err1 := strconv.Atoi(strings.Split(ports[p], "-")[1])
			if err0 == nil && err1 == nil {
				for i := 0; i < temporary1-temporary0+1; i++ {
					ports = append(ports, strconv.Itoa(temporary0+i))
				}
			}
		}
	}
	// turn ranges into individual values
	var portList = make(map[int]int)
	for p := 0; p < len(ports); p++ {
		if temp, err := strconv.Atoi(ports[p]); err == nil && !strings.Contains(ports[p], "-") {
			portList[p] = temp
		}
	}

	// do the same for ips, but take into account CiDR input
	var ips []string
	if strings.Contains(ip, "/") {
		ips = cidr.Expand(ip)
	} else {
		ips = strings.Split(ip, ",")
	}
	var ipList = make(map[int]string)
	for i := 0; i < len(ips); i++ {
		ipList[i] = ips[i]
	}

	if syn == false {
		reply := make(chan string)
		for ipIndex := 0; ipIndex < len(ipList); ipIndex++ {
			for i := range portList {
				go connect(ipList[ipIndex], portList[i], reply)
				scannedPorts[portList[i]] += <-reply + "\n"
			}
			// sort scannedPorts
			temp := ""
			sorted := make([]int, 0, len(scannedPorts))
			for k := range scannedPorts {
				sorted = append(sorted, k)
			}
			sort.Ints(sorted)
			for _, k := range sorted {
				if strings.Contains(scannedPorts[k], "open") {
					temp += scannedPorts[k]
				} else { // get rid of long lists of closed ports for ease of reading
					if strings.Contains(scannedPorts[k-1], "closed") && strings.Contains(scannedPorts[k+1], "closed") {
						temp += "|............closed\n"
					} else {
						temp += scannedPorts[k]
					}
				}
			}
			result[ipList[ipIndex]] = temp
			for j := range scannedPorts {
				delete(scannedPorts, j)
			}
		}
	} else {
		reply := make(chan string)
		for ipIndex := 0; ipIndex < len(ipList); ipIndex++ {
			for i := range portList {
				go SYN(ipList[ipIndex], portList[i], reply)
				scannedPorts[portList[i]] += <-reply + "\n"
			}
			// sort scannedPorts
			temp := ""
			sorted := make([]int, 0, len(scannedPorts))
			for k := range scannedPorts {
				sorted = append(sorted, k)
			}
			sort.Ints(sorted)
			for _, k := range sorted {
				if strings.Contains(scannedPorts[k], "open") {
					temp += scannedPorts[k]
				} else { // get rid of long lists of closed ports for ease of reading
					if strings.Contains(scannedPorts[k-1], "closed") && strings.Contains(scannedPorts[k+1], "closed") {
						temp += "|............closed\n"
					} else {
						temp += scannedPorts[k]
					}
				}
			}
			result[ipList[ipIndex]] = temp
			for j := range scannedPorts {
				delete(scannedPorts, j)
			}
		}
	}
	for scanned := range result {
		fmt.Println("\nHost " + scanned + ":")
		fmt.Println(result[scanned])
	}

}
