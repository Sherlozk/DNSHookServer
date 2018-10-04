# DNS Hook Server

一个基于`GO`的小型 DNS 解析服务器。但是对于这个应用的定位是，方便不能配置 host 的移动端设备。可以拦截特定的域名解析，使其解析到指定的 IP，所以命其名为DNS Hook。设计参考：[xdns](https://github.com/allenm/xdns)

关于 DNS 报文解析的部分，感谢：
[DNS 请求报文详解(上)](https://juejin.im/post/5ab719c151882577b45ef9d9#heading-9)
[DNS 请求报文详解(下)](https://juejin.im/post/5ab71be3f265da238d50acac)

## Rely
    
    $ go get github.com/imroc/biu

## Usage
``` go
$ sudo go run dns.go -h                                                                                                                                   
  -dnsListPath string
    	dns hook config file path (default "./lk-dns.conf")
  -remoteDns string
    	Forwarding DNS server (default "8.8.8.8")
```

### config
配置文件的写法基本和 host 相同。支持`#`注释，支持单行多域名。
```go
#单独行注释
127.0.0.1 www.baidu.com

127.0.0.1 www.google.com #行内注释

127.0.0.1 www.google.com www.baidu.com
```
