package main

import (
	"Bit-Pit/server"
	"flag"
)

var (
	RootNode         bool
	RemoteHost       string
	RemotePort       int
	LocalHost        string
	LocalPort        int
	LocalRootID      string
	Token            string
	TLS              bool
	DisableWebServer bool
	Threads          int
	DEBUG            bool
	WebVisitToken    string
	Subnet           string
)

func main() {
	// // checkroot
	// func() {
	// 	if syscall.Getuid() != 0 {
	// 		log.Fatal("This program must be run as root")
	// 	}
	// }()

	ReadConifg()
	if RootNode {
		if Token == "" {
			panic("Token is required for node")
		}
		server.InitAsRoot(LocalHost, LocalPort, Token, [8]byte{0xc1}, TLS, DisableWebServer, WebVisitToken, Subnet)
	} else {
		server.InitAsChild(RemoteHost, LocalHost, RemotePort, Token, TLS, Threads, DisableWebServer, WebVisitToken, Subnet)
	}
}

func ReadConifg() {
	flag.BoolVar(&TLS, "T", false, "use TLS")
	flag.BoolVar(&RootNode, "Root", false, "root node")
	flag.StringVar(&RemoteHost, "H", "127.0.0.1", "remote host")
	flag.IntVar(&RemotePort, "P", 18808, "remote port")
	flag.IntVar(&LocalPort, "p", 18808, "local port")
	flag.StringVar(&LocalHost, "l", "::", "local host")
	flag.StringVar(&Token, "t", "", "token")
	flag.BoolVar(&DisableWebServer, "dws", false, "disable web server")
	flag.StringVar(&WebVisitToken, "webtoken", "", "web visit token")
	flag.BoolVar(&DEBUG, "debug", false, "debug mode")
	flag.IntVar(&Threads, "th", 1, "Threads for connection")
	flag.StringVar(&Subnet, "subnet", "fd00::/64", "subnet for root node")
	flag.Parse()
	if WebVisitToken == "" {
		WebVisitToken = Token
	}
}
