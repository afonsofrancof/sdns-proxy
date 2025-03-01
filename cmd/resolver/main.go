package main

import (
	"bufio"
	"log"
	"os"
	"strings"

	"github.com/afonsofrancof/sdns-perf/internal/protocols/do53"
	"github.com/afonsofrancof/sdns-perf/internal/protocols/doh"
	"github.com/afonsofrancof/sdns-perf/internal/protocols/doq"
	"github.com/afonsofrancof/sdns-perf/internal/protocols/dot"
	"github.com/alecthomas/kong"
)

type CommonFlags struct {
	DomainName string `help:"Domain name to resolve" arg:"" required:""`
	QueryType  string `help:"Query type" enum:"A,AAAA,MX,TXT,NS,CNAME,SOA,PTR" default:"A"`
	Server     string `help:"DNS server to use" required:""`
	DNSSEC     bool   `help:"Enable DNSSEC validation"`
}

type DoHCmd struct {
	CommonFlags `embed:""`
	HTTP3       bool   `help:"Use HTTP/3" name:"http3"`
	Path        string `help:"The HTTP path for the POST request" name:"path" required:""`
	Proxy       string `help:"The Proxy to use with ODoH"`
}

type DoTCmd struct {
	CommonFlags
}

type DoQCmd struct {
	CommonFlags
}

type Do53Cmd struct {
	CommonFlags
}

type Listen struct {

}

var cli struct {
	Verbose bool `help:"Enable verbose logging" short:"v"`

	DoH  DoHCmd  `cmd:"doh" help:"Query using DNS-over-HTTPS" name:"doh"`
	DoT  DoTCmd  `cmd:"dot" help:"Query using DNS-over-TLS" name:"dot"`
	DoQ  DoQCmd  `cmd:"doq" help:"Query using DNS-over-QUIC" name:"doq"`
	Do53 Do53Cmd `cmd:"doq" help:"Query using plain DNS over UDP" name:"do53"`
	Listen Listen `cmd:"listen"`
}

func (c *Do53Cmd) Run() error {
	do53client, err := do53.New(c.Server)
	if err != nil {
		return err
	}
	defer do53client.Close()
	return do53client.Query(c.DomainName, c.QueryType, c.Server, c.DNSSEC)
}

func (c *DoHCmd) Run() error {
	dohclient, err := doh.New(c.Server, c.Path, c.Proxy)
	if err != nil {
		return err
	}
	defer dohclient.Close()
	return dohclient.Query(c.DomainName, c.QueryType, c.DNSSEC)
}

func (c *DoTCmd) Run() error {
	dotclient, err := dot.New(c.Server)
	if err != nil {
		return err
	}
	defer dotclient.Close()
	return dotclient.Query(c.DomainName, c.QueryType, c.Server, c.DNSSEC)
}

func (c *DoQCmd) Run() error {
	doqclient, err := doq.New(c.Server)
	if err != nil {
		return err
	}
	defer doqclient.Close()
	return doqclient.Query(c.DomainName, c.QueryType, c.DNSSEC)
}

func (l *Listen) Run() error {
    // Maps to store clients for reuse
    do53Clients := make(map[string]*do53.Do53Client)
    dotClients := make(map[string]*dot.DoTClient)
    doqClients := make(map[string]*doq.DoQClient)
    dohClients := make(map[string]*doh.DoHClient) // Using server+path+proxy as key
    
    scanner := bufio.NewScanner(os.Stdin)
    log.Println("Listening for input. Format: protocol domain server [options]")
    
    for scanner.Scan() {
        line := scanner.Text()
        fields := strings.Fields(line)
        
        if len(fields) < 3 {
            log.Printf("Invalid input: %s. Format should be 'protocol domain server [options]'", line)
            continue
        }
        
        protocol := fields[0]
        domain := fields[1]
        server := fields[2]
        
        // Default query type and DNSSEC setting
        queryType := "A"
        dnssec := false
        
        switch protocol {
        case "do53":
            // Parse additional options
            if len(fields) > 3 {
                queryType = fields[3]
            }
            if len(fields) > 4 && fields[4] == "dnssec" {
                dnssec = true
            }
            
            // Check if client exists, if not create it
            client, exists := do53Clients[server]
            if !exists {
                var err error
                client, err = do53.New(server)
                if err != nil {
                    log.Printf("Error creating Do53 client: %v", err)
                    continue
                }
                do53Clients[server] = client
            }
            
            err := client.Query(domain, queryType, server, dnssec)
            if err != nil {
                log.Printf("Error querying with Do53: %v", err)
            }
            
        case "dot":
            // Parse additional options
            if len(fields) > 3 {
                queryType = fields[3]
            }
            if len(fields) > 4 && fields[4] == "dnssec" {
                dnssec = true
            }
            
            client, exists := dotClients[server]
            if !exists {
                var err error
                client, err = dot.New(server)
                if err != nil {
                    log.Printf("Error creating DoT client: %v", err)
                    continue
                }
                dotClients[server] = client
            }
            
            err := client.Query(domain, queryType, server, dnssec)
            if err != nil {
                log.Printf("Error querying with DoT: %v", err)
            }
            
        case "doq":
            // Parse additional options
            if len(fields) > 3 {
                queryType = fields[3]
            }
            if len(fields) > 4 && fields[4] == "dnssec" {
                dnssec = true
            }
            
            client, exists := doqClients[server]
            if !exists {
                var err error
                client, err = doq.New(server)
                if err != nil {
                    log.Printf("Error creating DoQ client: %v", err)
                    continue
                }
                doqClients[server] = client
            }
            
            err := client.Query(domain, queryType, dnssec)
            if err != nil {
                log.Printf("Error querying with DoQ: %v", err)
            }
            
        case "doh":
            // DoH requires path parameter
            if len(fields) < 4 {
                log.Printf("DoH requires a path parameter")
                continue
            }
            
            path := fields[3]
            proxy := ""
            
            // Parse additional options
            if len(fields) > 4 {
                queryType = fields[4]
            }
            
            if len(fields) > 5 {
                if fields[5] == "dnssec" {
                    dnssec = true
                } else {
                    proxy = fields[5]
                }
            }
            
            if len(fields) > 6 && fields[6] == "dnssec" {
                dnssec = true
            }
            
            // Create a composite key for DoH clients
            key := server + ":" + path + ":" + proxy
            client, exists := dohClients[key]
            if !exists {
                var err error
                client, err = doh.New(server, path, proxy)
                if err != nil {
                    log.Printf("Error creating DoH client: %v", err)
                    continue
                }
                dohClients[key] = client
            }
            
            err := client.Query(domain, queryType, dnssec)
            if err != nil {
                log.Printf("Error querying with DoH: %v", err)
            }
            
        default:
            log.Printf("Unknown protocol: %s", protocol)
        }
    }
    
    if err := scanner.Err(); err != nil {
        return err
    }
    
    return nil
}


func main() {
	ctx := kong.Parse(&cli,
		kong.Name("dns-go"),
		kong.Description("A DNS resolver supporting DoH, DoT, and DoQ protocols"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}))

	err := ctx.Run()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
