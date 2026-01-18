package main

import (
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

			reqPayload := ""
			respPayload := ""

			for {
				data, _, _ := handle.ReadPacketData()

				ipHeaderSize := int(data[14]&0x0F) * 4
				tcpHeaderSize := int(data[46]>>4) * 4

				srcIp := uint32(data[26]) << 24 | uint32(data[27]) << 16 | uint32(data[28]) << 8 | uint32(data[29]) << 0
				dstIp := uint32(data[30]) << 24 | uint32(data[31]) << 16 | uint32(data[32]) << 8 | uint32(data[33]) << 0

				srcPort := uint16(data[34])<<8 | uint16(data[35])
				dstPort := uint16(data[36])<<8 | uint16(data[37])

				binderId := fmt.Sprintf("%d-%d-%d-%d", srcIp, srcPort, dstIp, dstPort)

				tcpSequenceNo := uint32(data[38])<<24 | uint32(data[39])<<16 | uint32(data[40])<<8 | uint32(data[41])<<0

				payloadSize := len(data) - ipHeaderSize - tcpHeaderSize

				packetType := ""
				if dstPort == 80 {
					packetType = "[REQUEST]"
				} else if srcPort == 80 {
					packetType = "[RESPONSE]"
				}

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

				payloadIndx := 14 + ipHeaderSize + tcpHeaderSize

				if packetType == "[REQUEST]" && payloadSize > 0 && (info == "[ACK] [PSH] " || info != "[ACK] [PSH] ") {
					reqPayload += string(data[payloadIndx:])
				}

				if packetType == "[RESPONSE]" && payloadSize > 0 && (info == "[ACK] [PSH] " || info != "[ACK] [PSH] ") {
					respPayload += string(data[payloadIndx:])
				}

				if packetType == "[REQUEST]" && info == "[ACK] [FIN] " {
					fmt.Print("\n--REQUEST--")
					fmt.Printf("\nPayload size: %d", payloadSize)
					fmt.Printf("\nSequence No: %d", tcpSequenceNo)
					fmt.Printf("\nBinder ID: %s", binderId)
					fmt.Printf("\nSource IP: %d:%d", srcIp, srcPort)
					fmt.Printf("\nDestination IP: %d:%d", dstIp, dstPort)
					fmt.Printf("\nIP header size: %d", ipHeaderSize)
					fmt.Printf("\nTCP header size: %d", tcpHeaderSize)
					fmt.Printf("\nPayload: %s", reqPayload)
					fmt.Println("\n----")

					reqPayload = ""
				}

				if packetType == "[RESPONSE]" && info == "[ACK] [FIN] " {
					fmt.Print("\n--RESPONSE--")
					fmt.Printf("\nPayload size: %d", payloadSize)
					fmt.Printf("\nSequence No: %d", tcpSequenceNo)
					fmt.Printf("\nBinder ID: %s", binderId)
					fmt.Printf("\nSource IP: %d:%d", srcIp, srcPort)
					fmt.Printf("\nDestination IP: %d:%d", dstIp, dstPort)
					fmt.Printf("\nIP header size: %d", ipHeaderSize)
					fmt.Printf("\nTCP header size: %d", tcpHeaderSize)
					fmt.Printf("\nPayload: %s", respPayload)
					fmt.Println("\n----")

					respPayload = ""
				}
			}
		}
	}
}
