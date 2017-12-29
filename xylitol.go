package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
)

var re = RegEx{}

type RegEx struct{

}

type Header struct {
	hname string
	hvals []string
}

type Message struct {
	method  string
	requri  string
	stcode  string
	reason  string
	headers []Header
	body    string
}

func NewMessage() *Message {
	return &Message{}
}

func (this *Message) Parse(s *string, addr *net.UDPAddr) {
	log.Println(*s)
	re_crlf := regexp.MustCompile(`(\r\n\r\n)|(\n\n)|(\r\r)`)
	*s = strings.TrimLeft(*s, `\r\n`)
	crlf_pos := re_crlf.FindStringIndex(*s)
	log.Println(crlf_pos[0])

}

func main() {
	fmt.Println("test")
	addr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 5060,
	}
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
	buf := make([]byte, 0xffff)
	for {
		len, addr, err := sock.ReadFromUDP(buf)
		if err == nil {
			s := string(buf[:len])
			log.Println(addr)
			msg := NewMessage()
			msg.Parse(&s, addr)
		}
	}
}
