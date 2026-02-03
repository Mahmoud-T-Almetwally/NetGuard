package packet

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func SendTCPReset(originalPayload []byte) error {
	packet := gopacket.NewPacket(originalPayload, layers.LayerTypeIPv4, gopacket.Default)

	// Get IPv4 Layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil 
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	newIP := &layers.IPv4{
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	newTCP := &layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		Seq:     tcp.Ack,
		Ack:     tcp.Seq + uint32(len(tcp.Payload)),
		RST:     true,
		ACK:     true,
		Window:  0,
	}

	if err := newTCP.SetNetworkLayerForChecksum(newIP); err != nil {
		return err
	}
	
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, newIP, newTCP); err != nil {
		return err
	}

	return sendRawPacket(newIP.DstIP, buffer.Bytes())
}

func sendRawPacket(destIP net.IP, data []byte) error {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.WriteTo(data, &net.IPAddr{IP: destIP})
	return err
}