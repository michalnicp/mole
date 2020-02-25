package ssh

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

type Forward struct {
	ID       uint
	Addr     string
	Listener net.Listener
	Conn     *ssh.ServerConn

	quit     chan struct{}
	quitOnce sync.Once
}

func (f *Forward) Close() error {
	var err error
	f.quitOnce.Do(func() {
		close(f.quit)
		err = f.Listener.Close()
	})
	return err
}

type Conn struct {
	sync.Mutex
	session ssh.Channel
}

func (c *Conn) Print(a ...interface{}) {
	if c.session != nil {
		fmt.Fprint(c.session, a...)
	}
}

func (c *Conn) Printf(format string, a ...interface{}) {
	if c.session != nil {
		fmt.Fprintf(c.session, format, a...)
	}
}

type Server struct {
	domain    string
	addr      string
	sshConfig *ssh.ServerConfig

	quit chan struct{}

	mu       *sync.Mutex
	nextID   uint
	listener net.Listener
	forwards map[uint]*Forward
	conns    map[*ssh.ServerConn]*Conn
}

func NewServer(addr string) (*Server, error) {

	// public key auth
	authorizedKeysBytes, err := ioutil.ReadFile("authorized_keys")
	if err != nil {
		return nil, fmt.Errorf("load authorized keys: %w", err)
	}

	authorizedKeysMap := map[string]struct{}{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, fmt.Errorf("parse authorized keys: %w", err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = struct{}{}
		authorizedKeysBytes = rest
	}

	// configure ssh server
	sshConfig := ssh.ServerConfig{
		ServerVersion: "SSH-2.0-mole",

		// NoClientAuth:  true,
		// KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		//     answers, err := client(
		//         "",                     // user
		//         "",                     // instructions
		//         []string{"password: "}, // questions
		//         []bool{false},          // echos
		//     )
		//     if err != nil {
		//         return nil, err
		//     }
		//     if len(answers) == 0 || answers[0] != "supersecret" {
		//         return nil, errors.New("invalid password")
		//     }
		//     return nil, nil
		// },

		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if _, ok := authorizedKeysMap[string(pubKey.Marshal())]; ok {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	// add ssh host key
	privateKeyBytes, err := ioutil.ReadFile("ssh_host_key")
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	sshConfig.AddHostKey(signer)

	s := Server{
		addr:      addr,
		sshConfig: &sshConfig,
		quit:      make(chan struct{}),
		mu:        &sync.Mutex{},
		forwards:  make(map[uint]*Forward),
		conns:     make(map[*ssh.ServerConn]*Conn),
	}

	return &s, nil
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = listener

	go func() {
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				select {
				case <-s.quit:
					return
				default:
					log.Printf("accept tcp: %v", err)
					continue
				}
			}

			// upgrade TCP connection to SSH connection
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.sshConfig)
			if err != nil {
				log.Printf("ssh handshake: %v", err)
				continue
			}

			// handle connection
			log.Printf("ssh connection: %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

			// store connection
			s.mu.Lock()
			s.conns[sshConn] = &Conn{}
			s.mu.Unlock()

			go s.handleRequests(sshConn, reqs)
			go s.handleChannels(sshConn, chans)
		}
	}()

	return nil
}

func (s *Server) Close() error {
	var errs []error

	close(s.quit)

	if err := s.listener.Close(); err != nil {
		errs = append(errs, err)
	}

	for _, forward := range s.forwards {
		if err := forward.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	for conn, _ := range s.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

func (s *Server) GetForwardAddr(id uint) (string, bool) {
	s.mu.Lock()
	forward, ok := s.forwards[id]
	s.mu.Unlock()
	return forward.Addr, ok
}

func (s *Server) handleRequests(conn *ssh.ServerConn, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case TCPIPForward:
			s.tcpipForward(conn, req)
		case CancelTCPIPForward:
			s.cancelTCPIPForward(req)
		default:
			log.Printf("unknown ssh request: %s", req.Type)
			s.discardRequest(req)
		}
	}
}

func (s *Server) discardRequest(req *ssh.Request) {
	if req.WantReply {
		req.Reply(false, nil)
	}
}

func (s *Server) handleChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel) error {
	for ch := range chans {
		switch t := ch.ChannelType(); t {
		case "session":
			s.session(sshConn, ch)
		default:
			log.Printf("unknown channel type: %s", t)
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
	return nil
}

func (s *Server) closeConn(conn *ssh.ServerConn) {
}

func (s *Server) session(conn *ssh.ServerConn, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("accept channel: %v", err)
		return
	}

	// store the channel
	s.mu.Lock()
	c := s.conns[conn]
	c.session = channel
	s.mu.Unlock()

	// print some info to the channel
	c.Lock()
	c.Print("mole version 0.0.0\r\n")
	for _, f := range s.forwards {
		if f.Conn == conn {
			c.Printf("forwarding %d.%s->?\r\n", f.ID, s.domain)
		}
	}
	c.Unlock()

	// start a go routine that waits for ctrl-c to be pressed
	go func() {
		defer conn.Close()

		buf := make([]byte, 1) // one byte buffer
		for {
			_, err := channel.Read(buf)
			if err == io.EOF {
				log.Printf("ssh connection closed")
				return
			}
			if err != nil {
				log.Printf("read error: %v", err)
				continue
			}
			if buf[0] == 3 { // ctrl-c pressed
				c.Print("^C\r\n")
				return
			}
		}
	}()

	for req := range requests {
		log.Printf("channel request: %s", req.Type)
	}
}

// func (s *Server) Subscribe() chan string {
//     s.mu.Lock()
//     defer s.mu.Unlock()

//     ch := make(chan string)
//     s.subscribers[ch] = struct{}{}
//     return ch
// }

func (s *Server) permitOpen(payload *TCPIPForwardRequest) bool {

	// only allow bind to loopback interface on non-privileged ports
	ip := net.ParseIP(payload.Addr)
	if ip == nil {
		ips, err := net.LookupIP(payload.Addr)
		if err != nil {
			log.Printf("lookup ip: %v", err)
			return false
		}
		for _, ip = range ips {
			if ip.To4() != nil {
				break
			}
		}
	}

	// TODO: make this configurable, see ssh_config(5) PermitOpen
	if !ip.IsLoopback() || payload.Port < 1024 {
		return false
	}

	return true
}

func (s *Server) tcpipForward(conn *ssh.ServerConn, req *ssh.Request) {
	var payload TCPIPForwardRequest
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Printf("unmarshal ssh %s request: %v", TCPIPForward, err)
		return
	}

	addr := net.JoinHostPort(payload.Addr, strconv.Itoa(int(payload.Port)))
	if !s.permitOpen(&payload) {
		log.Printf("port forward not permitted: %s", addr)
		return
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("listen tcp: %v", err)
		return
	}

	log.Printf("listening on %s", addr)

	quit := make(chan struct{})
	forward := Forward{
		Addr:     addr,
		Listener: listener,
		Conn:     conn,
		quit:     quit,
	}

	// If the ssh connection is closed suddenly, ensure that the listener gets closed
	// TODO: this should return if the listener is closed elsewhere ie cancelForward
	go func() {
		conn.Wait()
		forward.Close()
	}()

	// generate id, and store the forward
	s.mu.Lock()
	forward.ID = s.nextID
	s.nextID++
	s.forwards[forward.ID] = &forward
	c := s.conns[conn]
	s.mu.Unlock()

	// print the forwarding info
	c.Printf("forwarding http://%d.%s->%s\r\n", forward.ID, s.domain, addr)

	_, destPortStr, _ := net.SplitHostPort(listener.Addr().String())
	destPort, _ := strconv.Atoi(destPortStr)

	go func() {
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				select {
				case <-quit:
					return
				default:
					log.Printf("accept tcp: %v", err)
					continue
				}
			}

			originAddr, originPortStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
			originPort, _ := strconv.Atoi(originPortStr)

			payload := ForwardedTCPIPRequest{
				DestAddr:   payload.Addr,
				DestPort:   uint32(destPort),
				OriginAddr: originAddr,
				OriginPort: uint32(originPort),
			}

			// log.Printf("payload: %+v", payload)

			go func() {
				ch, reqs, err := conn.OpenChannel(ForwardedTCPIP, ssh.Marshal(&payload))
				if err != nil {
					log.Printf("open channel: %v", err)
					if err := tcpConn.Close(); err != nil {
						log.Printf("close tcp connection: %v", err)
					}
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					io.Copy(ch, tcpConn)
					ch.Close()
				}()
				go func() {
					io.Copy(tcpConn, ch)
					ch.Close()
				}()
			}()
		}
	}()
}

func (s *Server) cancelTCPIPForward(req *ssh.Request) {
	var payload CancelTCPIPForwardRequest
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Printf("parse %s request: %v", CancelTCPIPForward, err)
		return
	}

	addr := net.JoinHostPort(payload.Addr, strconv.Itoa(int(payload.Port)))

	s.mu.Lock()
	var forward *Forward
	for id, f := range s.forwards {
		if f.Addr == addr {
			forward = f
			delete(s.forwards, id)
			break
		}
	}
	s.mu.Unlock()
	if forward == nil {
		log.Printf("forward not found: %s", addr)
		return
	}

	if err := forward.Listener.Close(); err != nil {
		log.Printf("close forward: %v", err)
		return
	}
}
