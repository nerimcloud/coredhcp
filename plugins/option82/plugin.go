package option82

import (
	"encoding/binary"
	"errors"
	"net"
	"regexp"
	"strconv"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

var log = logger.GetLogger("plugins/option82")
var re = regexp.MustCompile(".*Ethernet.*/(\\d+)")
var base_addr net.IP
var netmask net.IPMask

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name:   "option82",
	Setup6: nil,
	Setup4: setup4,
}

// Handler4 handles DHCPv4 packets for the file plugin
func Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	relayOptions := req.RelayAgentInfo()
	if relayOptions != nil {
		circuitId := relayOptions.Get(dhcpv4.AgentCircuitIDSubOption)
		if len(circuitId) > 0 {
			result := re.FindSubmatch(circuitId)
			if result != nil {
				portId, _ := strconv.Atoi(string(result[1]))

				var network_address net.IP
				if base_addr == nil {
					network_address = req.GatewayIPAddr.Mask(netmask)
				} else {
					network_address = base_addr
				}

				network_address[len(network_address)-1] += byte(portId)
				client_address := network_address
				log.Errorf("Circuit ID: %s, Port ID: %d ; client_address: %s", string(circuitId), portId, client_address)

				// Set the client address
				resp.YourIPAddr = client_address

				// Use DHCP relay address as router address
				resp.Options.Update(dhcpv4.OptRouter(req.GatewayIPAddr))

				// Use DHCP relay address as server address
				resp.ServerIPAddr = req.GatewayIPAddr
				resp.UpdateOption(dhcpv4.OptServerIdentifier(req.GatewayIPAddr))
			}
		}
	}
	return resp, false
}

func setup4(args ...string) (handler.Handler4, error) {
	if len(args) < 1 {
		return nil, errors.New("need at least one netmask IP address")
	}
	netmaskIP := net.ParseIP(args[0])
	if netmaskIP.IsUnspecified() {
		return nil, errors.New("netmask is not valid, got: " + args[0])
	}
	netmaskIP = netmaskIP.To4()
	if netmaskIP == nil {
		return nil, errors.New("expected an netmask address, got: " + args[0])
	}
	netmask = net.IPv4Mask(netmaskIP[0], netmaskIP[1], netmaskIP[2], netmaskIP[3])
	if !checkValidNetmask(netmask) {
		return nil, errors.New("netmask is not valid, got: " + args[0])
	}

	if len(args) == 2 {
		base_addr = net.ParseIP(args[1])
	}

	log.Printf("loaded client netmask")
	return Handler4, nil
}

func checkValidNetmask(netmask net.IPMask) bool {
	netmaskInt := binary.BigEndian.Uint32(netmask)
	x := ^netmaskInt
	y := x + 1
	return (y & x) == 0
}
