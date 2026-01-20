package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type tcpstream struct {
	reader tcpreader.ReaderStream
	data   []byte
	net,
	transport gopacket.Flow
}

func (ts *tcpstream) Capture() {
	buf := make([]byte, 4096)

	for {
		noOfBytes, _ := ts.reader.Read(buf)
		ts.data = append(ts.data, buf[:noOfBytes]...)

		fmt.Printf("\nCopied %d bytes.", noOfBytes)
	}
}

type tcpstreamfactory struct{}

func (tsf *tcpstreamfactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	ts := &tcpstream{
		reader:    tcpreader.NewReaderStream(),
		net:       net,
		transport: transport,
	}

	go ts.Capture() // keep flushing ReaderStream in background to free buffer for next packet

	return &ts.reader
}

func main() {

	tsf := &tcpstreamfactory{}
	pool := tcpassembly.NewStreamPool(tsf)

	assembler := tcpassembly.NewAssembler(pool)

	nics, _ := pcap.FindAllDevs()
	for _, nic := range nics {
		if nic.Name == "en0" {
			handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)

			if err != nil {
				fmt.Printf("error opening device %d\n\n", err)
			}

			handle.SetBPFFilter("tcp port 80")

			packets := gopacket.NewPacketSource(handle, handle.LinkType())

			for packet := range packets.Packets() {
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp := tcpLayer.(*layers.TCP)
					assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
				}
			}
		}
	}
}
