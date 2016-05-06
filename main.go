package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"net"
	"math/big"
	"math/rand"
	"time"
	"github.com/miekg/dns"
	"github.com/ziutek/mymysql/mysql"
	_ "github.com/ziutek/mymysql/native" // Native engine
)

const (
	TIMEOUT time.Duration = 2 // seconds
)

type DnsRecordResult struct {
	Domain string
	RecordType string
	Value string
	IPDec *big.Int
}

var numDnsGoroutines = flag.Int("dns-goroutines", 10, "Number of DNS goroutines")
var dnsResolver = flag.String("dns-resolver", "8.8.8.8", "IP Address of DNS resolver")
var domainsFile = flag.String("domains-file", "./domains.txt", "Text file containing one domain per line")

var mysqlHost = flag.String("mysql-host", "127.0.0.1:3306", "MySQL host and password")
var mysqlUser = flag.String("mysql-user", "root", "MySQL user")
var mysqlPass = flag.String("mysql-pass", "", "MySQL password")
var mysqlDb   = flag.String("mysql-db", "", "Database name")

func main() {
	fmt.Println("Godines v0.1")
	fmt.Println("============")
	fmt.Println("")

	flag.Parse()

	file, err := os.Open(*domainsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "** ERR:", err)
		return
	}

	scanner := bufio.NewScanner(file)

	ch := make(chan string, 100)
	out := make(chan DnsRecordResult, 100)
	
	for i := 0; i < 50; i++ {
		go saveResults(out)
	}

	for i := 0; i < *numDnsGoroutines; i++ {
		go resolve(ch, out)
	}

	for scanner.Scan() {
		ch <- scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading file:", err)
	}


	time.Sleep(60 * time.Second)

	close(ch)
}

func saveResults(out chan DnsRecordResult) {
	db := mysql.New("tcp", "", *mysqlHost, *mysqlUser, *mysqlPass, *mysqlDb)
	err := db.Connect()
	if err != nil {
		panic(err)
	}

	ins, err := db.Prepare("INSERT INTO dns_records (`domain`, `type`, `value`, `ip_dec`) VALUES (?, ?, ?, ?)")
	if err != nil {
		panic(err)
	}

	for result := range out {
		ins.Bind(result.Domain, result.RecordType, result.Value, result.IPDec.String())
		_, err = ins.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "** ERR:", err)
		}
	}
}

func resolve(ch chan string, out chan DnsRecordResult) {
	recordTypes := []uint16{
		dns.TypeNS,
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeMX,
		dns.TypeSOA,
		dns.TypeCNAME,
		dns.TypeTXT,
	}

	for domain := range ch {
		for _, recordType := range recordTypes {
			// fmt.Println(domain)
			answer := queryDNS(domain, recordType)

			// Check that if we dont get any NS records to skip domain
			if recordType == dns.TypeNS && answer == nil {
				// fmt.Fprintf(os.Stderr, "** ERR: No NS records found, skipping domain - " + domain + "\n")
				break
			}

			for _, record := range answer {
				answerRR := dns.TypeToString[record.Header().Rrtype]
				recordString := getRecordString(answerRR, record)
				out <- DnsRecordResult{
					Domain: domain,
					RecordType: answerRR,
					Value: recordString,
					IPDec: ip2int(recordString),
				}
			}
		}
	}
}

// Convert the IP address to an Int (for MySql Storage)
func ip2int(IpAddrString string) *big.Int {
	IpAddr := net.ParseIP(IpAddrString);

	if IpAddr == nil {
		return big.NewInt(0)
	}

        IpInt := big.NewInt(0)
        // Check if we are dealing with v4/v6
        if IpBytes := IpAddr.To4(); IpBytes != nil {
                IpInt.SetBytes(IpBytes)
        } else {
                IpInt.SetBytes(IpAddr)
        }
	
	return IpInt
}

func getRecordString(recordType string, record dns.RR) string {
        if (recordType == "A") {
                return record.(*dns.A).A.String()
        }
        if (recordType == "AAAA") {
                return record.(*dns.AAAA).AAAA.String()
        }
        if (recordType == "NS") {
                return record.(*dns.NS).Ns
        }
        if (recordType == "MX") {
                return record.(*dns.MX).Mx
        }
        if (recordType == "TXT") {
                return record.(*dns.TXT).Txt[0]
        }
        if (recordType == "SOA") {
              	// Return the mail box of the SOA
            	return record.(*dns.SOA).Mbox
        }
	if (recordType == "CNAME") {
                return record.(*dns.CNAME).Target
        }

	return ""
}

func queryDNS(domain string, recordType uint16) []dns.RR {
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{dns.Fqdn(domain), recordType, dns.ClassINET}

	c := new(dns.Client)
	c.ReadTimeout = TIMEOUT * 1e9
	
	resolver := getDnsResolver()

	in, _, err := c.Exchange(m1, resolver)

	if err != nil {
		fmt.Fprintln(os.Stderr, "** ERR:", err, " ~ ", domain)
		return nil
	}

	if len(in.Answer) == 0 {
		return nil
	}

	return in.Answer
}

func getDnsResolver() string {
	return "45.32.3.108:53"

	if rand.Int() %2 == 0 {
		return "45.32.3.108:53"
	}
	return "198.98.52.140:53"
}
