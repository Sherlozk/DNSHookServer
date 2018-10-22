package main

import(
	"net"
	"log"
	"github.com/imroc/biu"
	"strings"
	"strconv"
	"os"
	"bufio"
	"regexp"
	"bytes"
	"encoding/binary"
	"flag"
	"time"
)




type dnsHeader struct {
	id []byte  		//标识字段，客户端会解析服务器返回的DNS应答报文，获取ID值与请求报文设置的ID值做比较，如果相同，则认为是同一个DNS会话。
	qr int64  		//0表示查询报文，1表示响应报文;
	opcode int64 	//0（标准查询），其他值为1（反向查询）和2（服务器状态请求）,[3,15]保留值;
	aa int64		//表示授权回答（authoritative answer）-- 这个比特位在应答的时候才有意义，指出给出应答的服务器是查询域名的授权解析服务器;
	tc int64		//表示可截断的（truncated）--用来指出报文比允许的长度还要长，导致被截断;
	rd int64		//表示期望递归(Recursion Desired) -- 这个比特位被请求设置，应答的时候使用的相同的值返回。如果设置了RD，就建议域名服务器进行递归解析，递归查询的支持是可选的;
	ra int64		//表示支持递归(Recursion Available) -- 这个比特位在应答中设置或取消，用来代表服务器是否支持递归查询;
	z int64			//保留值，暂未使用;
	rcode int64		//0 : 没有错误;1 : 报文格式错误(Format error);2 : 服务器失败(Server failure);3 : 域名不存在(Name Error);4 : 域名服务器不支持查询类型(Not Implemented);5 : 拒绝(Refused)
	qdcount int64	//报文请求段中的问题记录数
	ancount int64	//报文回答段中的回答记录数
	nscount int64	//报文授权段中的授权记录数
	arcount int64	//报文附加段中的附加记录数
}

type dnsQuestion struct {
	qname []byte	//域名
	qtype []byte	//查询的协议类型
	qclass []byte	//查询的类,比如，IN代表Internet
}

type dnsAnswer struct {
	aname []byte	//域名
	atype []byte	//查询的协议类型
	aclass []byte	//查询的类,比如，IN代表Internet
	ttl int64		//time to live存活时间
	rdlen int64		//数据长度
	rdata []byte	//数据记录
}

type dnsRespone struct {
	header dnsHeader
	question dnsQuestion
	answer dnsAnswer
}

var qtypeDic = map[int64]string{
1:"A", 			//IPv4地址
2:"NS",			//名字服务器
5:"CNAME",		//规范名称定义主机的正式名字的别名
6:"SOA",		//开始授权标记一个区的开始
11:"WKS",		//熟知服务定义主机提供的网络服务
12:"PTR",		//指针把IP地址转化为域名
13:"HINFO",		//主机信息给出主机使用的硬件和操作系统的表述
15:"MX",		//邮件交换把邮件改变路由送到邮件服务器
28:"AAAA",		//IPv6地址
252:"AXFR",		//传送整个区的请求
255:"ANY",		//对所有记录的请求
}

func getHeader(data []byte) dnsHeader {
	flags := data[2:4]

	flagsStr := biu.BytesToBinaryString(flags)
	//log.Printf("flags:%x  flagsBit: %q ",flags,flagsStr)

	header := &dnsHeader{
		id:data[0:2],
		qr:StringToInt64(flagsStr[1:2]),
		opcode:StringToInt64(flagsStr[2:6]),
		aa:StringToInt64(flagsStr[6:7]),
		tc:StringToInt64(flagsStr[7:8]),
		rd:StringToInt64(flagsStr[8:9]),
		ra:StringToInt64(flagsStr[10:11]),
		z:StringToInt64(flagsStr[11:14]),
		rcode:StringToInt64(flagsStr[14:18]),
		qdcount:BytesToInt64(data[4:6]),
		ancount:BytesToInt64(data[6:8]),
		nscount:BytesToInt64(data[6:8]),
		arcount:BytesToInt64(data[10:12]),

	}

	return *header
}


func getQuestion(data []byte) dnsQuestion {

	qnameBytes := data[12:len(data)-4]

	question := &dnsQuestion{
		qname:qnameBytes,
		qtype: data[len(data)-4:len(data)-2],	//BytesToInt64(data[len(data)-4:len(data)-2]),
		qclass:data[len(data)-2:len(data)],		//BytesToInt64(data[len(data)-2:len(data)]),
	}

	return *question
}

func forwardRequst2(data []byte, remoteDns string) []byte {
	// 创建连接
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP(remoteDns),
		Port: 53,
	})
	if err != nil {
		log.Println("连接失败!", err)
		return nil
	}
	t := time.Now()

	socket.SetDeadline(t.Add(time.Duration(5*time.Second)))

	defer socket.Close()
	// 发送数据
	_, err = socket.Write(data)
	if err != nil {
		log.Println("发送数据失败!", err)
		return nil
	}
	// 接收数据
	revdata := make([]byte, 4096)
	rn, remoteAddr, err := socket.ReadFromUDP(revdata)
	if err != nil {
		log.Println("从",remoteAddr,"””读取数据失败!", err)
		return nil
	}
	//log.Println(rn, remoteAddr)
	//log.Printf("%x\n", revdata[:rn])

	return revdata[:rn]
}

func readConfig(dnsListPath string) map[string]string {
	var dnsMap = map[string]string{}
	var dnsListFile, _ = os.OpenFile(dnsListPath, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	defer dnsListFile.Close()
	dnsListScanner := bufio.NewScanner(dnsListFile)
	for dnsListScanner.Scan() {
		ip := ""
		domain := ""

		//单行扫描文件
		dnsList := dnsListScanner.Text()

		//去除注释
		if string([]byte(dnsList)[:1]) == "#" || dnsList == "" {
			continue
		}
		dnsList = strings.Split(dnsList,"#")[0]

		//取出记录

		dnsArr := strings.Split(dnsList, " ")
		if len(dnsArr) >= 2 {
			for _,dnsStr := range dnsArr {
				if isIP(dnsStr) {
					ip = dnsStr
				}else if isDomain(dnsStr) {
					domain = dnsStr
				}
				if ip != "" && domain != "" {
					dnsMap[domain] = ip
				}
				domain = ""
			}
		}else {
			log.Printf("dns 配置错误，请检查：%s",dnsList)
		}

	}
	log.Printf("current dns setting: %q",dnsMap)
	if len(dnsMap) != 0 {
		return dnsMap
	}
	return nil
}

func hookDNS(header dnsHeader, question dnsQuestion, ip string) []byte {

	respone := dnsRespone{}

	respone.header.id = header.id
	respone.header.qr = 1
	respone.header.opcode = 0
	respone.header.aa = 0
	respone.header.tc = 0
	respone.header.rd = 1
	respone.header.ra = 0
	respone.header.z = 0
	respone.header.rcode = 0
	respone.header.qdcount = 1
	respone.header.ancount = 1
	respone.header.nscount = 0
	respone.header.arcount = 0

	respone.question = question

	respone.answer.aname = question.qname
	respone.answer.atype = question.qtype
	respone.answer.aclass = question.qclass
	respone.answer.ttl = 600
	respone.answer.rdlen = 4
	respone.answer.rdata = ipAddrToByte(ip)


	return reslove(respone)


}

func reslove(respone dnsRespone) []byte {
	buf := make([]byte,30+len(respone.question.qname)+2)
	offset := len(respone.question.qname)

	buf[0] = respone.header.id[0]
	buf[1] = respone.header.id[1]

	buf[2] = byte(0x00 | respone.header.qr<<7 | respone.header.opcode<<3 | respone.header.aa<<2 | respone.header.tc<<1 | respone.header.rd)
	buf[3] = byte(0x00 | respone.header.ra<<7 | respone.header.z<<4 | respone.header.rcode)
	buf[4] = byte(0x00)
	buf[5] = byte(0x00 | respone.header.qdcount)
	buf[6] = byte(0x00)
	buf[7] = byte(0x00 | respone.header.ancount)
	buf[8] = byte(0x00)
	buf[9] = byte(0x00)
	buf[10] = byte(0x00)
	buf[11] = byte(0x00)

	writebytesToBuffer(buf,respone.question.qname, 12)
	writebytesToBuffer(buf,respone.question.qtype, 12+int64(offset))
	writebytesToBuffer(buf,respone.question.qclass, 14+int64(offset))

	offset += 16
	writebytesToBuffer(buf,[]byte{0xc0,0x0c}, int64(offset))

	offset += 2
	writebytesToBuffer(buf, respone.answer.atype, int64(offset))
	writebytesToBuffer(buf, respone.answer.aclass, int64(offset)+2)
	writebytesToBuffer(buf, linkBytes([]byte{0x00,0x00},Int64ToBytes(respone.answer.ttl)), int64(offset)+4)
	writebytesToBuffer(buf,Int64ToBytes(respone.answer.rdlen), int64(offset)+8)
	writebytesToBuffer(buf,respone.answer.rdata,int64(offset)+10)


	//log.Printf("hook: %x",buf)


	return buf
}



// 工具类


//ip 地址转[]byte
func ipAddrToByte(ipAddr string) []byte {
	bits := strings.Split(ipAddr, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	return []byte{byte(b0),byte(b1),byte(b2),byte(b3)}
}


//域名解析
func parseDomain(buf []byte) string {
	parts := make([]string,0)
	for i := 0; i<len(buf);{
		len := int(buf[i])

		if len == 0 {break}

		offset := i+1
		parts = append(parts, string(buf[offset:offset+len]))

		i = offset + len
	}

	return strings.Join(parts,".")
}

//将一个 byte 数组写入另一个 byte 数组
func writebytesToBuffer(buffer []byte, buf []byte, n int64) []byte {
	for _,b := range buf {
		buffer[n] = b
		n++
	}
	return buffer
}

//连接两个 byte 数组，并返回一个新的byte数组
func linkBytes(b1 []byte, b2 []byte) []byte {
	var buf bytes.Buffer
	buf.Write(b1)
	buf.Write(b2)
	return buf.Bytes()
}


//int64转 byte 数组
func Int64ToBytes(i int64) []byte {
	b_buf := bytes.NewBuffer([]byte{})
	binary.Write(b_buf, binary.BigEndian, i)
	return b_buf.Bytes()[len(b_buf.Bytes())-2:]
}

//byte 数组转 int64
func BytesToInt64(buf []byte) int64 {
	bufStr := biu.BytesToBinaryString(buf)
	bufint64,_ :=  strconv.ParseInt(bufStr[len(bufStr)-5:len(bufStr)-1],10,64)
	return bufint64
}


//字符串转 int64
func StringToInt64(str string) int64 {
	intStr,_ := strconv.ParseInt(str,10,64)
	return intStr
}

//正则判断字符串是否为 IP
func isIP(str string) bool {
	ipRe := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	return ipRe.MatchString(str)
}

//判断字符串是否为域名
func isDomain(str string) bool {
	domainRe := regexp.MustCompile(`([a-z0-9--]{1,200})\.([a-z]{2,10})(\.[a-z]{2,10})?`)
	return domainRe.MatchString(str)
}



func main() {
	var remoteDns string
	var dnsListPath string
	flag.StringVar(&remoteDns,"remoteDns","8.8.8.8","Forwarding DNS server")
	flag.StringVar(&dnsListPath, "dnsListPath","./lk-dns.conf","dns hook config file path")
	flag.Parse()

	//读取 dns 代理配置
	dnsMap := readConfig(dnsListPath)

	//监听53端口，接收 dns 解析请求
	listener,err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port:53})

	//t := time.Now()
	//
	//listener.SetDeadline(t.Add(time.Duration(5*time.Second)))

	if err != nil {
		 log.Println(err)
		 return
	}
	defer listener.Close()

	log.Println("Listening Local："+listener.LocalAddr().String())

	data := make([]byte, 1024)

	for {
		n, remoteAddr, readErr := listener.ReadFromUDP(data)

		//解析 dns 解析请求
		header := getHeader(data[:n])
		question := getQuestion(data[:n])
		//log.Println(header)
		//log.Println(question)

		if readErr != nil {
			log.Printf("error during read: %s",readErr)
		}

		//log.Printf("<%s> %x \n", remoteAddr, data[:n])

		//hookDNS(header, question,"127.0.0.1")

		//如果没有配置需要代理的域名或者请求解析的域名不在配置文件内，转发给8.8.8.8处理
		//这里不做协议类型做判断，完全由用户需要而选择拦截与否
		if dnsMap == nil || dnsMap[parseDomain(question.qname)] == ""{
			log.Printf("forward %s to %s",parseDomain(question.qname),remoteDns)
			_, writeErr := listener.WriteToUDP(forwardRequst2(data[:n],remoteDns), remoteAddr)

			if writeErr != nil {
				log.Printf("error during write: %s", writeErr)
			}
			continue
		}
		//log.Printf("real : %x", forwardRequst2(data[:n],remoteDns))
		//log.Printf("hook : %x", hookDNS(header,question,dnsMap[parseDomain(question.qname)]))
		rsp := hookDNS(header,question,dnsMap[parseDomain(question.qname)])
		_, writeErr := listener.WriteToUDP(rsp, remoteAddr)
		//_, writeErr := listener.WriteToUDP(forwardRequst2(data[:n],remoteDns), remoteAddr)

		if writeErr != nil {
			log.Printf("error during write: %s", writeErr)
		}else {
			log.Printf("hook %s return %s",parseDomain(question.qname), dnsMap[parseDomain(question.qname)] )
		}




	}
}
