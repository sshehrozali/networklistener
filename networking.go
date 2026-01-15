package main

import (
	"encoding/hex"
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
				fmt.Printf("packets: %s", hex.Dump(data))
				
				sourceIP := data[26:30]
				dstPort := uint16(data[36])<<8 | uint16(data[37])

				fmt.Printf("Source IP: %d.%d.%d.%d:%d", sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3], dstPort)

				// fmt.Printf("Payload: %s", string(data[54:]))
			}
		}
	}
}
