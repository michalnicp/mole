package ssh

const (
	TCPIPForward       = "tcpip-forward"
	CancelTCPIPForward = "cancel-tcpip-forward"
	ForwardedTCPIP     = "forwarded-tcpip"
)

type TCPIPForwardRequest struct {
	Addr string
	Port uint32
}

type TCPIPForwardSuccess struct {
	Port uint32
}

type ForwardedTCPIPRequest struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type CancelTCPIPForwardRequest struct {
	Addr string
	Port uint32
}
