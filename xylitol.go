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
var re_empty_line *regexp.Regexp
var re_crlf *regexp.Regexp
var re_wsp *regexp.Regexp
var re_start_line *regexp.Regexp
var re_hname *regexp.Regexp
var re_comma *regexp.Regexp

func InitRegEx() {
	re_empty_line = regexp.MustCompile(`(\r\n\r\n)|(\n\n)|(\r\r)`)
	re_crlf = regexp.MustCompile(`((\r\n)|(\n)|(\r))`)
	re_wsp = regexp.MustCompile(`((\r\n)|(\r)|(\n))[ \t]+`)
	re_start_line = regexp.MustCompile(`(([A-Z]+) ([^ ]+) )?SIP/2\.0( ([1-6][1-6][0-9]) ([^\r\n]+))?((\r\n)|(\r)|(\n))`)
	re_hname = regexp.MustCompile(`([^\s:]+)(\s*:\s*)`)
	re_comma = regexp.MustCompile(`\s*,\s*`)
}

type RegEx struct {
}

type Header struct {
	hname string
	hvals []string
}

func NewHeader() *Header {
	hdr := new(Header)
	hdr.hname = ""
	hdr.hvals = []string{}
	return hdr
}

type Message struct {
	method  string
	requri  string
	stcode  string
	reason  string
	headers []*Header
	body    string
}

func NewMessage() *Message {
	msg := new(Message)
	return msg
}

func (this *Message) Parse(s *string, addr *net.UDPAddr) bool {
	log.Println(*s)
	*s = strings.TrimLeft(*s, `\r\n`)
	// Empty-Line
	empty_line_pos := re_empty_line.FindStringIndex(*s)
	log.Println("Empty-Line Pos:", empty_line_pos[0])
	for i, v := range empty_line_pos {
		fmt.Println(i, v)
	}
	this.body = (*s)[empty_line_pos[1]:]
	fmt.Println("body=[" + this.body + "]")
	buf := re_wsp.ReplaceAllString((*s)[:empty_line_pos[0]], " ")
	buf = re_crlf.ReplaceAllString(buf, "\n")
	ary := strings.Split(buf, "\n")
	if this.ParseStartLine(&(ary[0])) == false {
		return false
	}
	for _, line := range ary[1:] {
		if this.ParseHeader(&line) == false {
			return false
		}
	}
	return true
}

func (this *Message)ParseStartLine(s *string) bool {
	sl := re_start_line.FindStringSubmatchIndex(*s)
	if len(sl) != 14 {
		fmt.Println(len(sl))
		return false
	}
	if sl[4] != -1 && sl[5] != -1 &&
		sl[6] != -1 && sl[7] != -1 {
		this.method = (*s)[sl[4]:sl[5]]
		this.requri = (*s)[sl[6]:sl[7]]
		this.stcode = ""
		this.reason = ""
	} else if sl[10] != -1 && sl[11] != -1 &&
		sl[12] != -1 && sl[13] != -1 {
		this.method = ""
		this.requri = ""
		this.stcode = (*s)[sl[10]:sl[11]]
		this.reason = (*s)[sl[12]:sl[13]]
	}
	fmt.Println("method=[" + this.method + "] requri=[" + this.requri + "]")
	fmt.Println("stcode=[" + this.stcode + "] reason=[" + this.reason + "]")
	return true
}

func (this *Message) ParseHeader(s *string) bool {
	pos := re_hname.FindStringSubmatchIndex(*s)
	hdr := NewHeader()
	hdr.hname = (*s)[:pos[3]]
	hdr.hvals = re_comma.Split((*s)[pos[1]:], -1)
	this.headers = append(this.headers, hdr)
	return true
}

func (this *Message)IsRequest() bool {
	if len(this.method) > 0 && len(this.requri) > 0 {
		return true
	}
	return false
}

func (this *Message)IsResponse() bool {
	if len(this.stcode) > 0 && len(this.reason) > 0 {
		return true
	}
	return false
}

func ProcRequest(msg *Message) {
}

func ProcResponse(msg *Message) {
}

func main() {
	fmt.Println("test")
	InitRegEx()
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
			if msg.Parse(&s, addr) == false {
				continue
			}
			if msg.IsRequest() {
				ProcRequest(msg)
			} else if msg.IsResponse() {
				ProcResponse(msg)
			}
		}
	}
}
