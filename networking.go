package main

import (
	// "encoding/hex"
	"fmt"

	"github.com/google/gopacket/pcap"
)

func main() {
	nics, _ := pcap.FindAllDevs()

	for _, nic := range nics {
		if nic.Name == "en0" {
			handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever) // keep capturing until packet arrives

			if err != nil {
				fmt.Printf("error opening device %d\n\n", err)
			}

			handle.SetBPFFilter("tcp port 80")

			for {
				data, _, _ := handle.ReadPacketData()

				// IP and TCP header sizes
				ipHeaderSize := int(data[14]&0x0F) * 4
				fmt.Printf("\nIP header size: %d", ipHeaderSize)

				tcpHeaderSize := int(data[46]>>4) * 4
				fmt.Printf("\nTCP header size: %d", tcpHeaderSize)

				// IPs
				srcIPBytes := data[26:30]
				dstIPBytes := data[30:34]

				srcIP := fmt.Sprintf("%d.%d.%d.%d", srcIPBytes[0], srcIPBytes[1], srcIPBytes[2], srcIPBytes[3])
				dstIP := fmt.Sprintf("%d.%d.%d.%d", dstIPBytes[0], dstIPBytes[1], dstIPBytes[2], dstIPBytes[3])

				// Ports
				srcPort := uint16(data[34])<<8 | uint16(data[35])
				dstPort := uint16(data[36])<<8 | uint16(data[37])

				fmt.Printf("\nSource IP: %s:%d", srcIP, srcPort)
				fmt.Printf("\nDestination IP: %s:%d", dstIP, dstPort)

				// BinderID to stich packets
				binderId := fmt.Sprintf("%s-%d-%s-%d", srcIP, srcPort, dstIP, dstPort)
				fmt.Printf("\nBinder ID: %s", binderId)

				// TCP sequence no
				tcpSequenceNoBytes := data[38:42]
				tcpSequenceNo := uint32(tcpSequenceNoBytes[0]) << 24 | uint32(tcpSequenceNoBytes[1]) << 16 | uint32(tcpSequenceNoBytes[2]) << 8 | uint32(tcpSequenceNoBytes[3]) << 0
				fmt.Printf("\nSequence No: %d", tcpSequenceNo)

				// Payload size
				payloadSize := len(data) - ipHeaderSize - tcpHeaderSize
				fmt.Printf("Payload size: %d", payloadSize)

				// Packet type
				packetType := ""
				if (dstPort == 80) {
					packetType = "[REQUEST]"
				} else if (srcPort == 80) {
					packetType = "[RESPONSE]"
				}

				// TCP handshake
				flags := data[47]
				info := ""
				if (flags & 0x02) != 0 {
					info += "[SYN] "
				}
				if (flags & 0x10) != 0 {
					info += "[ACK] "
				}
				if (flags & 0x08) != 0 {
					info += "[PSH] "
				}
				if (flags & 0x01) != 0 {
					info += "[FIN] "
				}
				if (flags & 0x04) != 0 {
					info += "[RST] "
				}

				fmt.Printf("\nFlags: %s", info)
				fmt.Printf("\nType: %s\n", packetType)

				payloadIndx := 14 + ipHeaderSize + tcpHeaderSize

				// if a packet size is greater than payload index, then payload exists
				if len(data) > payloadIndx {
					fmt.Printf("\n%s", string(data[payloadIndx:]))
				}

				// fmt.Printf("Payload: %s", string(data[66:]))
				fmt.Println("\n----")
			}
		}
	}
}
