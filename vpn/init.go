package vpn

import loging "github.com/zreigz/tuntap-vpn/utils"

var logger = loging.GetLogger()

var MTU = 1400

const (
	IFACE_BUFSIZE = 2000
)
