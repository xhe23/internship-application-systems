package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"time"
	"strconv"
	"os/signal"
	"syscall"
)

type Message struct {
	Host 	string
	Delay	time.Duration
	Error	error
	Seq		uint16
	Size	int
	Ttl		int
	Recv 	int
}

func buildRequest(id int, seq uint16, size int) []byte {
	buffer := []byte("req")
    p := make([]byte, size)
    copy(p[8:], bytes.Repeat(buffer, (size - 8) / len(buffer) + 1))

    p[0] = 8
    p[1] = 0
    p[2] = 0
    p[3] = 0
    p[4] = uint8(id >> 8)
    p[5] = uint8(id & 0xff)
    p[6] = uint8(seq >> 8)
    p[7] = uint8(seq & 0xff)

    checklen := len(p)
    s := uint32(0)
    for i := 0; i < (checklen - 1); i += 2 {
        s += uint32(p[i+1])<<8 | uint32(p[i])
    }
    if checklen & 1 == 1 {
        s += uint32(p[checklen-1])
    }
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    p[2] ^= uint8(^s & 0xff)
    p[3] ^= uint8(^s >> 8)

    return p
}

func SendPing(target string, res chan Message, wait int, timeout int, count int, ipv6 bool, ttlLimit int) {
	var ( 
		conn 	net.Conn
		err		error
		host	*net.IPAddr
		pid 		int			= os.Getpid() & 0xffff
		pingLength 	int			= 64
		seq 		uint16 		= 0
		duration time.Duration 	= 0
		recv = 0
	)

	host, err = net.ResolveIPAddr("ip", target)
	if err != nil {
        var ip string
        if host != nil {
            ip = host.IP.String()
        } else {
            ip = target
        }
		res <- Message {Host: ip, 
						Delay: 0, 
						Error: err, 
						Seq: 0}
		close(res)
		return
	}
	if ipv6 {
		conn, err = net.Dial("ip6:icmp", host.IP.String())
	} else {
		conn, err = net.Dial("ip4:icmp", host.IP.String())
	}
	if err != nil {
		res <- Message{	Host: host.IP.String(),
						Delay: 0,
						Error: err,
						Seq: 0}
		close(res)
		return
	}
	for ; count == 0 || int(seq) < count; seq++ {
		duration = 0
		if seq >= 0xffff {
			seq = 0
		}
		request := buildRequest(pid, seq, pingLength)
		start := time.Now()
		writesize, err := conn.Write(request)
        if err != nil || writesize != pingLength {
            res <- Message{Delay: 0, Error: err, Host: host.IP.String(), Seq: seq}
            time.Sleep(time.Millisecond * time.Duration(wait))
            continue
        }

        conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(timeout)))

        recvBuffer := make([]byte, 1024)
        for {
            readsize, err := conn.Read(recvBuffer)
			duration = time.Now().Sub(start)
			rttl := int(recvBuffer[8])
            rid := int(recvBuffer[24]) << 8 | int(recvBuffer[25])
            rseq := int(recvBuffer[26]) << 8 | int(recvBuffer[27])
			rcode := int(recvBuffer[21])
			if ttlLimit != 0 && rttl > ttlLimit {
				err = fmt.Errorf("Exceeded maximum ttl.")
			}
			readsize -= 20	// remove size of ip header
            if err != nil {
                res <- Message{Delay: 0, Error: err, Host: host.IP.String(), Seq: uint16(seq), Size: readsize, Ttl: rttl}
                break
            } else if rcode != 0 || rseq != int(seq) || int(rid) != pid {
                continue
            } else {
				recv++
                res <- Message {Delay: duration, Error: err, Host: host.IP.String(), Seq: uint16(rseq), Size: readsize, Ttl: rttl, Recv: recv}
                break
            }
        }
        time.Sleep(time.Duration(wait) * time.Millisecond - duration)
	}
	
	close(res)
}

func printHelp() {
	fmt.Println("usage:\tgo run ping.go [-h] [-v] [-c count] [-i wait] [-m ttl] [-t timeout] host")
	fmt.Println("options:\t-h help")
	fmt.Println("\t\t-v IPv6")
	fmt.Println("\t\t-c set number of requests")
	fmt.Println("\t\t-i wait n milliseconds between requests")
	fmt.Println("\t\t-m set maximum ttl limit")
	fmt.Println("\t\t-t set maximum timeout in milliseconds")
}

func parseArgs(args []string) (ttl int, count int, ipv6 bool, timeout int, wait int, host string, err error) {
	timeout	= 1000
	wait 	= 1000
	err		= nil

	if len(args) < 2 {
		err = fmt.Errorf("Not enough arguments.")
		return
	} else if len(args) == 2 {
		if val := args[1]; val[0] == '-' {
			err = fmt.Errorf("User manual.")
			return
		}
		host = args[1]
	} else {
		i := 1
		for ; i < len(args) - 1; i++ {
			option := args[i]
			switch option {
			case "-v":
				ipv6 = true
			case "-c":
				i++
				if val, e := strconv.Atoi(args[i]); err == nil {
					if val <= 0 {
						err = fmt.Errorf("Count must be positive")
						return
					}
					count = val
				} else {
					err = e
					return
				}
			case "-i":
				i++
				if val, e := strconv.Atoi(args[i]); err == nil {
					wait = val
				} else {
					err = e
					return
				}
			case "-m":
				i++
				if val, e := strconv.Atoi(args[i]); err == nil {
					ttl = val
				} else {
					err = e
					return
				}
			case "-t":
				i++
				if val, e := strconv.Atoi(args[i]); err == nil {
					timeout = val
				} else {
					err = e
					return
				}
			default:
				err = fmt.Errorf("Invalid arguments.")
				return
			}
			if i == len(args) - 1 {
				err = fmt.Errorf("Invalid arguments.")
				return
			}
		}
		host = args[len(args) - 1]
		if host[0] == '-' {
			err = fmt.Errorf("Invalid arguments.")
			return
		}
	}
	return
}

func main() {
	var (
		channel 	chan Message = make(chan Message, 100)
		sigChannel	chan os.Signal = make(chan os.Signal)
		seq			int = 0
		recv		int = 0
	)
	ttl, count, ipv6, timeout, wait, host, err := parseArgs(os.Args)
	if err != nil {
		fmt.Printf("Go Ping: ")
		fmt.Println(err)
		printHelp()
		return
	}
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<- sigChannel
		fmt.Printf("\n--- %s ping statistics ---\n", host)
		fmt.Printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n", seq + 1, 
			recv, 100 - float32(recv) * 100 / float32(seq + 1))
		os.Exit(0)
	}()
	go SendPing(host, channel, wait, timeout, count, ipv6, ttl)
	for msg := range channel {
		seq = int(msg.Seq)
		if msg.Error != nil {
			fmt.Printf("Go Ping: %s\n", msg.Error)
			fmt.Printf("Request timeout for icmp_seq %d\n", msg.Seq)
        } else {
			recv = msg.Recv
            fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%s\n", msg.Size, msg.Host, msg.Seq, msg.Ttl, msg.Delay)
        }
	}
	fmt.Printf("\n--- %s ping statistics ---\n", host)
	fmt.Printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n", seq + 1, 
		recv, 100 - float32(recv) * 100 / float32(seq + 1))
}