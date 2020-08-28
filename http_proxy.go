package main

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"net/url"
)

// httpsDialer
type httpsDialer struct{}

// HTTPSDialer is a https proxy: one that makes network connections on tls.
var (
	HttpsDialer = httpsDialer{}
	TlsConfig   = &tls.Config{
		InsecureSkipVerify: true,
	}
)

func (d httpsDialer) Dial(network, addr string) (c net.Conn, err error) {
	c, err = tls.Dial("tcp", addr, TlsConfig)
	if err != nil {
		fmt.Println(err)
	}
	return
}

// httpProxy is a HTTP/HTTPS connect proxy.
type httpProxy struct {
	host     string
	haveAuth bool
	username string
	password string
	uri      *url.URL
	forward  proxy.Dialer
}

func newHTTPProxy(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	s := new(httpProxy)
	s.host = uri.Host
	s.forward = forward
	s.uri = uri
	if uri.User != nil {
		s.haveAuth = true
		s.username = uri.User.Username()
		s.password, _ = uri.User.Password()
	}
	return s, nil
}

func (s *httpProxy) Dial(network, addr string) (net.Conn, error) {

	var (
		c   net.Conn
		err error
	)
	// create the initial connection
	if s.forward != nil {
		c, err = s.forward.Dial(network, s.host)
		//log.Printf("[%s] dialed proxy with forwarder at: %s", network, s.host)
	} else {
		c, err = net.Dial(network, s.host)
		//log.Printf("[%s] dialed proxy at: %s", network, s.host)
	}

	if err != nil {
		return nil, err
	}

	if s.uri.Scheme == "https" {
		// do ssl handshake
		tlsConn := tls.Client(c, TlsConfig)
		if err = tlsConn.Handshake(); err != nil {
			c.Close()
			log.Printf("couldn't establish tls connection to [%s]: %s\n", network, err)
			return nil, err
		}
		return tlsConn, nil
	}

	//log.Printf("connected to proxy at: %s", s.host)
	return c, nil
}

func init() {
	proxy.RegisterDialerType("http", newHTTPProxy)
	proxy.RegisterDialerType("https", newHTTPProxy)
}
