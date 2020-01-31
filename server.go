package ldapserver

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Server is an LDAP server.
type Server struct {
	Listener     net.Listener
	ReadTimeout  time.Duration  // optional read timeout
	WriteTimeout time.Duration  // optional write timeout
	wg           sync.WaitGroup // group of goroutines (1 by client)
	chDone       chan bool      // Channel Done, value => shutdown

	// OnNewConnection, if non-nil, is called on new connections.
	// If it returns non-nil, the connection is closed.
	OnNewConnection func(c net.Conn) error

	// Handler handles ldap message received from client
	// it SHOULD "implement" RequestHandler interface
	Handler Handler
}

//NewServer return a LDAP Server
func NewServer() *Server {
	return &Server{
		chDone: make(chan bool),
	}
}

// Handle registers the handler for the server.
// If a handler already exists for pattern, Handle panics
func (s *Server) Handle(h Handler) {
	if s.Handler != nil {
		panic("LDAP: multiple Handler registrations")
	}
	s.Handler = h
}

// ListenAndServe listens on the TCP network address s.Addr and then
// calls Serve to handle requests on incoming connections.  If
// s.Addr is blank, ":389" is used.
func (s *Server) ListenAndServe(addr string, ch chan error, options ...func(*Server)) {
	var e error
	s.Listener, e = net.Listen("tcp", addr)

	if e != nil {
		ch <- fmt.Errorf("error creating listener: %s", e)
		return
	}

	if ch != nil {
		close(ch)
	}

	log.Printf("listening on %s\n", addr)

	for _, option := range options {
		option(s)
	}

	s.serve()
}

// ListenAndServeTLS doing the same as ListenAndServe,
// but uses tls.Listen instead of net.Listen. If
// s.Addr is blank, ":686" is used.
func (s *Server) ListenAndServeTLS(addr string, certFile string, keyFile string, ch chan error, options ...func(*Server)) {

	if addr == "" {
		addr = ":686"
	}

	cert, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		ch <- fmt.Errorf("error creating certificate chain: %s", e)
		return
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	s.Listener, e = tls.Listen("tcp", addr, &tlsConfig)
	if e != nil {
		ch <- fmt.Errorf("error creating listener: %s", e)
		return
	}

	if ch != nil {
		close(ch)
	}

	log.Printf("listening on %s\n", addr)

	for _, option := range options {
		option(s)
	}

	s.serve()
}

// Handle requests messages on the ln listener
func (s *Server) serve() {
	defer s.Listener.Close()

	if s.Handler == nil {
		log.Panicln("No LDAP Request Handler defined")
	}

	i := 0

	for {
		select {
		case <-s.chDone:
			log.Print("Stopping server")
			s.Listener.Close()
			return
		default:
		}

		rw, err := s.Listener.Accept()

		if s.ReadTimeout != 0 {
			rw.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}
		if s.WriteTimeout != 0 {
			rw.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			log.Println(err)
		}

		cli := s.newClient(rw)

		i = i + 1
		cli.Numero = i
		log.Printf("Connection client [%d] from %s accepted", cli.Numero, cli.rwc.RemoteAddr().String())
		s.wg.Add(1)
		go cli.serve()
	}
}

// Return a new session with the connection
// client has a writer and reader buffer
func (s *Server) newClient(rwc net.Conn) (c *client) {
	c = &client{
		srv: s,
		rwc: rwc,
		br:  bufio.NewReader(rwc),
		bw:  bufio.NewWriter(rwc),
	}
	return c
}

// Termination of the LDAP session is initiated by the server sending a
// Notice of Disconnection.  In this case, each
// protocol peer gracefully terminates the LDAP session by ceasing
// exchanges at the LDAP message layer, tearing down any SASL layer,
// tearing down any TLS layer, and closing the transport connection.
// A protocol peer may determine that the continuation of any
// communication would be pernicious, and in this case, it may abruptly
// terminate the session by ceasing communication and closing the
// transport connection.
// In either case, when the LDAP session is terminated.
func (s *Server) Stop() {
	close(s.chDone)
	log.Print("gracefully closing client connections...")
	s.wg.Wait()
	log.Print("all clients connection closed")
}
