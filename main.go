package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"github.com/miekg/dns"
	"github.com/ziutek/mymysql/mysql"
	_ "github.com/ziutek/mymysql/native" // Native engine
)

type DnsRecordResult struct {
	Domain string
	RecordType uint16
	Value string
	IPDec int64
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

	go saveResults(out)

	for i := 0; i < *numDnsGoroutines; i++ {
		go resolve(ch, out)
	}

	for scanner.Scan() {
		ch <- scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading file:", err)
	}
	close(ch)
}

func saveResults(out chan DnsRecordResult) {
	db := mysql.New("tcp", "", *mysqlHost, *mysqlUser, *mysqlPass, *mysqlDb)
	err := db.Connect()
	if err != nil {
		panic(err)
	}

	ins, err := db.Prepare("INSERT INTO dns_records (`domain`, `type`, `value`) VALUES (?, ?, ?)")
	if err != nil {
		panic(err)
	}

	for result := range out {
		ins.Bind(result.Domain, dns.TypeToString[result.RecordType], result.Value)
		_, err = ins.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "** ERR:", err)
		}
	}
}

func resolve(ch chan string, out chan DnsRecordResult) {
	recordTypes := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeNS,
		dns.TypeMX,
		dns.TypeSOA,
		dns.TypeCNAME,
	}

	for domain := range ch {
		for _, recordType := range recordTypes {
			fmt.Println(domain)
			answer := queryDNS(domain, recordType)
			for _, record := range answer {
				out <- DnsRecordResult{
					Domain: domain,
					RecordType: recordType,
					Value:  record.String(),
				}
			}
		}
	}
}

func getRecord(RecordType uint16, record dns.RR) string {

        recordType := dns.TypeToString[RecordType]

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
	in, _, err := c.Exchange(m1, *dnsResolver + ":53")

	if err != nil {
		fmt.Fprintln(os.Stderr, "** ERR:", err)
		return nil
	}

	if len(in.Answer) == 0 {
		return nil
	}

	return in.Answer
}
