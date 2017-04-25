#!/usr/bin/python
# -*- encoding: utf-8 -*-

import socket, re, hashlib, sys

class AddrSpec:

  def __init__(self, buf):
    m = re.match(r'([^:]+):', buf)
    self.scheme, buf = m.group(1), buf[m.end():]
    if self.scheme == 'sip':
      m = re.match(r'(([^@]+)@)?([^?;]+)', buf)
      self.userinfo, hostport = m.group(2), m.group(3)
      buf = buf[m.end():]
      m = re.match(r'([^:]+)(:(\d+))?', hostport)
      self.host, self.port = m.group(1), m.group(3)
    else:
      self.host = self.port = None
    m = re.match(r'[^?]*', buf)
    self.uri_prms, self.headers = m.group(0), buf[m.end():]


class NameAddr(AddrSpec):

  def __init__(self, buf):
    m = re.match(r'(("[^"]*")\s*)?', buf)
    self.display_name, buf = m.group(0), buf[m.end():]
    m = re.match(r'\s*<([^>]+)>', buf)
    if m != None:
      self.addr_spec, buf = m.group(1), buf[m.end():]
    else:
      m = re.match(r'[^;]+', buf)
      self.addr_spec, buf = m.group(0), buf[m.end():]
    self.prms = buf
    AddrSpec.__init__(self, self.addr_spec)


class Header:

  def __init__(self, name, vals):
    self.name, self.vals = name, vals

  def __str__(self):
    return self.name + ': ' + ', '.join(self.vals) + "\r\n"


class Message:

  def __init__(self, buf):
    buf = re.sub(r'^((\r\n)|(\r)|(\n))*', "", buf)
    m = re.search(r'((\r\n\r\n)|(\r\r)|(\n\n))', buf)
    self.body = buf[m.end():]
    buf = re.sub(r'\n[ \t]+',' ', re.sub(r'\r\n?', "\n", buf[:m.start()]))
    ary = buf.split("\n")
    m = re.match(r'(([A-Z]+) ([^ ]+) )?SIP\/2\.0( (\d+) ([^\n]+))?', ary[0])
    self.method, self.requri, self.stcode, self.reason = \
      m.group(2), m.group(3), m.group(5), m.group(6)
    self.hdrs = []
    for buf in ary[1:]:
      name, buf = re.split(r'\s*:\s*', buf, 1)
      self.hdrs.append(Header(name, re.split(r'\s*,\s*', buf)))

  def __str__(self):
    if self.method != None:
      s = self.method + ' ' + self.requri + " SIP/2.0\r\n"
    else:
      s = 'SIP/2.0 ' + self.stcode + " " + self.reason + "\r\n"
    for hdr in self.hdrs:
      s += str(hdr)
    return s + "\r\n" + self.body

  def search(self, name1, name2 = ''):
    for i, h in enumerate(self.hdrs):
      if name1.lower() == h.name.lower() or name2.lower() == h.name.lower():
        return i
    return None

  def rsearch(self, name1, name2 = ''):
    pos = None
    for i, h in enumerate(self.hdrs):
      if name1.lower() == h.name.lower() or name2.lower() == h.name.lower():
        pos = i
    return pos

  def gen_resp(self, stcode, reason, contacts = []):
    hs=["call-id","i","from","f","to","t","via","v","cseq","record-route"]
    resp = Message("SIP/2.0 " + stcode + " " + reason + "\r\n\r\n")
    for h in self.hdrs:
      if h.name.lower() in hs:
        resp.hdrs.append(h)
    if contacts != []:
      resp.hdrs.append(Header("Contact", contacts))
    resp.hdrs.append(Header("Content-Length", ["0"]))
    return resp


class Proxy:

  def __init__(self, domain, ip, port):
    self.location_service = {}
    self.domain, self.ip, self.port = domain, ip, port
    self.via = "SIP/2.0/UDP " + self.ip + ":" + str(self.port) + ";branch="
    self.rr = "<sip:" + self.ip + ":" + str(self.port) + ";lr>"
    self.sr = "<sip:" + self.ip + ":" + str(self.port) + ">"
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.sock.bind((self.ip, self.port))

  def start(self):
    while True:
      buf, addr = self.sock.recvfrom(0xffff)
      print "<" * 72
      print "received from " + addr[0] + " " + str(addr[1])
      print "-" * 8
      print buf
      msg = Message(buf)
      if msg.method != None:
        viapos = msg.search("via", "v")
        msg.hdrs[viapos].vals[0] += ";received=" + addr[0]
        m = re.search(";\s*rport", msg.hdrs[viapos].vals[0])
        if m != None:
          tmpvia = msg.hdrs[viapos].vals[0]
          tmpvia = tmpvia[:m.end()] + "=" + str(addr[1]) + tmpvia[m.end():]
          msg.hdrs[viapos].vals[0] = tmpvia
        branch = msg.hdrs[viapos].vals[0] + " "
        branch += msg.hdrs[msg.search("call-id", "i")].vals[0] + " "
        cseq = msg.hdrs[msg.search("cseq", "")].vals[0]
        m = re.match(r'(\d+)\s+(\S+)', msg.hdrs[msg.search("cseq")].vals[0])
        cseq_num, cseq_method = m.group(1), m.group(2)
        if cseq_method == "ACK":
          cseq_method = "INVITE"
        branch += cseq_num + " " + cseq_method
        branch = 'z9hG4bK' + hashlib.md5(branch).hexdigest()
        msg.hdrs[viapos].vals.insert(0, self.via + branch)
        self.proc_request(msg)
      else:
        self.proc_response(msg)

  def proc_request(self, msg):
    # (1) Proxy-Requireがあったらエラー
    pos = msg.search("proxy-require")
    if pos != None:
      if msg.method != "ACK":
        unsupported = msg.hdrs[pos]
        resp = msg.gen_resp("420", "Bad Extension")
        resp.hdrs.append(unsupported)
        proc_response(resp)
      return
    # (2) Request-URIが自身を指しているかを判定する
    requri = AddrSpec(msg.requri)
    if self.comp(requri, self.domain, self.ip, self.port):
      if msg.method == "REGISTER":
        return self.proc_register(msg)
      if self.location_service.has_key(requri.userinfo):
        msg.requri = self.location_service[requri.userinfo]
      else:
        if msg.method != "ACK":
          self.proc_response(msg.gen_resp("404", "Not Found"))
        return
      requri = AddrSpec(msg.requri)
    # (3) Max-Forwardsの確認
    pos = msg.search("max-forwards")
    if pos == None:
      msg.hdrs.append(Header("Max-Forwards", ["70"]))
    elif msg.hdrs[pos].vals[0] == "0":
      if msg.method != "ACK":
        resp = msg.gen_resp("420", "Too Many Hops")
        self.proc_response(resp)
      return
    else:
      msg.hdrs[pos].vals[0] = str(int(msg.hdrs[pos].vals[0]) -1)
    # (4) Record-Routeヘッダを処理
    pos = msg.rsearch("record-route")
    if pos == None:
      msg.hdrs.append(Header("Record-Route", [self.rr]))
    else:
      msg.hdrs[pos].vals.append(self.rr)
    # (5) Routeヘッダの先頭が自分だったら削除する
    pos = msg.search("route")
    if pos != None:
      route = NameAddr(msg.hdrs[pos].vals[0])
      if self.comp(route, self.domain, self.ip, self.port):
        del msg.hdrs[pos].vals[0]
        if msg.hdrs[pos].vals == []:
          del msg.hdrs[pos]
    # (6) 送信先判定、Routeヘッダ値、なければRequest-URIで判定
    pos = msg.search("route")
    if pos != None:
      target = NameAddr(msg.hdrs[pos].vals[0])
    else:
      target = requri
    self.send(str(msg), target.host, target.port)

  def proc_register(self, msg):
    addr = NameAddr(msg.hdrs[msg.search("to", "t")].vals[0])
    contact = msg.hdrs[msg.search("contact", "m")].vals[0]
    self.location_service[addr.userinfo] = contact
    resp = msg.gen_resp("200", "OK", [contact])
    resp.hdrs.append(Header("Service-Route", [self.sr]))
    self.proc_response(resp)

  def proc_response(self, msg):
    # (1) 先頭のViaを削除
    pos = msg.search("via", "v")
    del msg.hdrs[pos].vals[0]
    if msg.hdrs[pos].vals == []:
      del msg.hdrs[pos]
      pos = msg.search("via", "v")
    # (2) 中継先判定
    m = re.match(r'SIP\s*\/\s*2\.0\s*\/\s*UDP\s+([^\s;:]+)(\s*:\s*(\d+))?',
      msg.hdrs[pos].vals[0])
    desthost, destport = m.group(1), m.group(3)
    prms = msg.hdrs[pos].vals[0][m.end():]
    m = re.search(r';\s*received\s*=\s*([^\s;]+)', prms)
    if m != None:
      desthost = m.group(1)
    m = re.search(r';\s*rport\s*=\s*(\d+)', prms)
    if m != None:
      destport = m.group(1)
    # (3) 送信
    self.send(str(msg), desthost, destport)

  def comp(self, requri, domain, ip, port):
    if requri.host == domain:
      return True
    if requri.host == ip:
      requri_port = requri.port
      if requri_port == None:
        requri_port = 5060
      elif requri_port == "":
        requri_port = 5060
      if str(requri_port) == str(port):
        return True
    return False

  def send(self, buf, host, port):
    if port == None:
      port = 5060
    elif port == "":
      port = 5060
    else:
      port = int(port)
    if self.ip == host and self.port == port:
      return
    self.sock.sendto(buf, 0, (host, port))
    print '>' * 72
    print 'send to ' + host + ' ' + str(port)
    print '-' * 8
    print buf

px = Proxy(sys.argv[1], sys.argv[2], int(sys.argv[3]))
print "ok"
px.start()    
