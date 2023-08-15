package socks5

const (
	S5Version = 5
	S5AuthVer = 1
)

const (
	MethodNoAuth uint8 = iota
	MethodGSSAPI
	MethodAccPwd
	// X'03' - X'7F' IANA ASSIGNED
	// X'80' - X'FE' RESERVED FOR PRIVATE METHODS

	MethodNoAcceptable uint8 = 0xFF
)

const (
	_ uint8 = iota
	CommandConnect
	CommandBind
	CommandUdpAssociate
)

const (
	_ uint8 = iota
	AddrTypeIPv4
	_
	AddrTypeDomain
	AddrTypeIPv6
)
