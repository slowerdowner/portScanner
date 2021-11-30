package main

import (
	"fmt"
	"flag"
//	"strconv"
//	"strings"
	"net"
	"sort"
//	"os"
//	"log"
)

var (
	helpFlag = flag.Bool("h", false, "Show this help")
	startFlag = flag.Int("start", 1, "Start port for Scan")
	stopFlag = flag.Int("stop", 1024, "Stop port for Scan")
	threadFlag = flag.Int("t", 100, "Concurrency variable")
)

const usage = "`portScanner` [options] <ip_address...>"

func main() {
	flag.Parse()
	var (
		portStart	int
		portStop	int
		threads		int
	)

	if *helpFlag || flag.NArg() == 0 {
		fmt.Println(usage)
		flag.PrintDefaults()
		return
	}

	portStart = *startFlag
	portStop = *stopFlag
	if portStart > portStop {
		portStart = 1
		fmt.Println("Port Start cannot be higher than Port Stop")
	}

	threads = *threadFlag

	//fmt.Println(target, portStart, portStop, threads)
	for _, target := range flag.Args() {
		realIp := net.ParseIP(target)
		if realIp == nil {
			fmt.Println(target, "not a valid IP address")
			continue
		}
		portScanner(target, portStart, portStop, threads)
	}
}
// this method users a 'Worker Pool' of goroutines to manage concurrent tasks
// to avoid an unordered list of ports, we use a separate thread to pass the portscan results back to main
// this organizing step removes the need for the WaitGroup
func portScanner(tar string, start, stop, threads int) {
	fmt.Printf("[+] Scanning %s\n", tar)

	ports := make(chan int, threads) // creates a buffered channel capable of holding 100 items before blocking
	results := make(chan int)	// separate channel to communicate results
	var openPorts []int	// slice to store the results

	for i := 0; i < cap(ports); i++ {	// loops based on size of channel
		go worker(tar, ports, results)
		}
	go func() {	// result-gathering work needs to start before more than 100 items of work can continue
		for i := start; i <= stop; i++ {
			ports <- i	// send a port on the ports channel to the worker
		}
	}()
	for i := start - 1; i < stop; i++ {	// result gathering loop receives on result channel 1024 times
		port := <- results
		if port != 0 {
			openPorts = append(openPorts, port)
		}
	}
	close(ports)
	close(results)
	sort.Ints(openPorts)	// this sort provides the wait buffer to prevent program from closing

	if len(openPorts) < 1 {
		fmt.Printf("\t...no open ports found from %d-%d\n", start, stop)
	} else {
		for _, port := range openPorts {
			fmt.Printf("\t%d open\n", port)
		}
		fmt.Print("[=] Complete.\n\n")
	}
}

func worker(tar string, ports, results chan int) {	// worker now receives two channels
	for p := range ports {	// use range to continously receive from the ports channel, looping until the channel is closed
		address := fmt.Sprintf("%s:%d", tar, p)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			results <- 0	// send a zero if port is closed
			continue
		}
		conn.Close()
		results <- p	// send the port number if port is open
	}
}
