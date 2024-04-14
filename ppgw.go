package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

var (
	server                string
	domain                string
	rawURL                string
	downURL               string
	port                  int
	maxSystemCommandDelay int
	waitdelay             string
	resolver              *net.Resolver
	inputFiles            inputFlags
	inputFile             string
	outputFile            string
	yamlhashFile          string
	interval              string
	sleeptime             string
	apiURL                string
	secret                string
	reckey                string
	testNodeURL           string
	extNodeStr            string
	testProxy             string
	dnslist               string
	reload                bool
	closeall              bool
	wsPort                string
	net_rec_num           string
	now_node              bool
	spec_node             string
)

var orange = "\033[38;5;208m"
var green = "\033[32m"
var red = "\033[31m"
var reset = "\033[0m"

type inputFlags []string

type ClashNode struct {
	Node string `json:"name"`
	Type string `json:"type"`
	Now  string `json:"now,omitempty"`
}

type ClashAPIResponse struct {
	Proxies map[string]ClashNode `json:"proxies"`
}

type ConfigResponse struct {
	Mode string `json:"mode"`
}

type PingResult struct {
	Node     string
	Duration time.Duration
}

type PingResponse struct {
	Delay int `json:"delay"`
}

type Downloader struct {
	URL        string
	OutputFile string
	UserAgent  string
	Timeout    time.Duration
}

// ws catch
type ConnectionInfo struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Connections   []Connection `json:"connections"`
}

type Connection struct {
	ID       string   `json:"id"`
	Metadata Metadata `json:"metadata"`
	Upload   int      `json:"upload"`
	Download int      `json:"download"`
}

type Metadata struct {
	Network         string `json:"network"`
	Type            string `json:"type"`
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationPort string `json:"destinationPort"`
	Host            string `json:"host"`
	DNSMode         string `json:"dnsMode"`
	ProcessPath     string `json:"processPath"`
	SpecialProxy    string `json:"specialProxy"`
}

type DomainInfo struct {
	Domain   string
	Download int64
	Upload   int64
	ClientIP string
}

type DomainInfoList []DomainInfo

type LastConnectionInfo struct {
	LastDownloadTotal int64
	LastUploadTotal   int64
}

func main() {

	flag.Var(&inputFiles, "input", "Input YAML files")
	flag.StringVar(&outputFile, "output", "output.yaml", "Output YAML file")
	flag.StringVar(&inputFile, "dnsinput", "", "dns input YAML file")
	flag.StringVar(&yamlhashFile, "yamlhashFile", "", "Hash YAML file")
	flag.StringVar(&domain, "domain", "", "domain")
	flag.StringVar(&rawURL, "rawURL", "", "rawURL")
	flag.StringVar(&downURL, "downURL", "", "downURL")
	flag.StringVar(&server, "server", "", "DNS server to use")
	flag.StringVar(&interval, "interval", "", "sub interval")
	flag.StringVar(&sleeptime, "sleeptime", "", "sleeptime")
	flag.StringVar(&testProxy, "testProxy", "", "http testProxy")
	flag.StringVar(&dnslist, "dnslist", "", "dnslist")
	flag.IntVar(&port, "port", 53, "DNS port")

	//clashapi
	flag.StringVar(&apiURL, "apiurl", "", "Clash API")
	flag.StringVar(&secret, "secret", "", "Clash secret")
	flag.StringVar(&spec_node, "spec_node", "", "specified node by name")
	flag.StringVar(&reckey, "reckey", "", "netrec reckey")
	flag.StringVar(&testNodeURL, "test_node_url", "", "test_node_url")
	flag.StringVar(&extNodeStr, "ext_node", "", "ext_node")
	flag.StringVar(&waitdelay, "waitdelay", "1000", "node delay")
	flag.IntVar(&maxSystemCommandDelay, "cpudelay", 300, "CPU delay")
	flag.BoolVar(&reload, "reload", false, "reload yaml")
	flag.BoolVar(&closeall, "closeall", false, "close all connections.")
	flag.BoolVar(&now_node, "now_node", false, "now_node.")
	//ws catch
	flag.StringVar(&wsPort, "wsPort", "", "wsPort")
	flag.StringVar(&net_rec_num, "net_rec_num", "", "net_rec_num")

	flag.Parse()
	//net_rec
	if wsPort != "" && secret != "" && reckey != "" {
		max_rec, err := strconv.Atoi(net_rec_num)
		if err != nil {
			max_rec = 5000
		}
		wsURL := "ws://127.0.0.1:" + wsPort + "/connections?token=" + secret
		fmt.Printf("\n" + green + "[PaoPaoGW REC]" + reset + "Start NET REC :" + wsPort + " \n")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		domainInfoMap := make(map[string]*DomainInfo)
		lastConnectionInfoMap := make(map[string]LastConnectionInfo)
		var domainInfoList DomainInfoList
		var mutex sync.Mutex

		go func() {
			for {
				conn, _, err := websocket.Dial(ctx, wsURL, nil)
				if err != nil {
					fmt.Printf("\n" + red + "[PaoPaoGW REC]" + reset + "Failed to dial WebSocket.\n")
					time.Sleep(5 * time.Second)
					continue
				}
				defer conn.Close(websocket.StatusInternalError, "PPGW NET_REC ERR")

				// Increase the read limit
				conn.SetReadLimit(10 * 1024 * 1024)

				for {
					var connectionInfo ConnectionInfo
					err := wsjson.Read(ctx, conn, &connectionInfo)
					if err != nil {
						fmt.Printf("\n" + red + "[PaoPaoGW REC]" + reset + "Failed to read WebSocket message.\n")
						break
					}

					mutex.Lock()
					for _, connection := range connectionInfo.Connections {
						destination := connection.Metadata.Host
						if destination == "" {
							destination = connection.Metadata.DestinationIP
						}

						lastInfo, exists := lastConnectionInfoMap[connection.ID]
						if !exists {
							lastConnectionInfoMap[connection.ID] = LastConnectionInfo{
								LastDownloadTotal: int64(connection.Download),
								LastUploadTotal:   int64(connection.Upload),
							}
						} else {
							download := int64(connection.Download) - lastInfo.LastDownloadTotal
							upload := int64(connection.Upload) - lastInfo.LastUploadTotal

							if domainInfo, ok := domainInfoMap[destination]; ok {
								domainInfo.Download += download
								domainInfo.Upload += upload
							} else {
								domainInfoMap[destination] = &DomainInfo{
									Domain:   destination,
									Download: download,
									Upload:   upload,
									ClientIP: connection.Metadata.SourceIP,
								}
							}

							lastConnectionInfoMap[connection.ID] = LastConnectionInfo{
								LastDownloadTotal: int64(connection.Download),
								LastUploadTotal:   int64(connection.Upload),
							}
						}
					}

					if len(domainInfoMap) > max_rec*2 {
						var trimmedList []DomainInfo
						for _, info := range domainInfoMap {
							trimmedList = append(trimmedList, *info)
						}
						sort.Slice(trimmedList, func(i, j int) bool {
							return trimmedList[i].Download+trimmedList[i].Upload > trimmedList[j].Download+trimmedList[j].Upload
						})
						if len(trimmedList) > max_rec {
							trimmedList = trimmedList[:max_rec]
						}
						domainInfoMap = make(map[string]*DomainInfo)
						for i := range trimmedList {
							domainInfoMap[trimmedList[i].Domain] = &trimmedList[i]
						}
					}
					mutex.Unlock()
				}
			}
		}()
		for range time.Tick(3 * time.Second) {
			mutex.Lock()
			domainInfoList = nil
			for _, info := range domainInfoMap {
				domainInfoList = append(domainInfoList, *info)
			}
			sort.Sort(domainInfoList)
			recPath := "/etc/config/clash/clash-dashboard/rec_data/" + reckey
			os.MkdirAll(recPath, 0755)
			newFilePath := recPath + "/data.csv.new"
			oldFilePath := recPath + "/data.csv.old"
			currentFilePath := recPath + "/data.csv"
			file, err := os.Create(newFilePath)
			if err != nil {
				fmt.Printf("\n" + red + "[PaoPaoGW REC]" + reset + "Failed to create CSV file.\n")
				mutex.Unlock()
				continue
			}
			defer file.Close()
			writer := csv.NewWriter(file)
			if err := writer.Write([]string{"Domain", "Download", "Upload", "ClientIP"}); err != nil {
				fmt.Printf("\n" + red + "[PaoPaoGW REC]" + reset + "Error writing CSV header.\n")
				continue
			}
			for _, info := range domainInfoList {
				row := []string{info.Domain, formatBytes(info.Download), formatBytes(info.Upload), info.ClientIP}
				if err := writer.Write(row); err != nil {
					fmt.Printf("\n" + red + "[PaoPaoGW REC]" + reset + "Error writing CSV data.\n")
					continue
				}
			}
			writer.Flush()
			if err := writer.Error(); err != nil {
				fmt.Printf("\n" + red + "[PaoPaoGW REC]" + reset + "Error flushing CSV data.\n")
			}
			file.Close()
			if _, err := os.Stat(currentFilePath); err == nil {
				os.Rename(currentFilePath, oldFilePath)
			}

			if err := os.Rename(newFilePath, currentFilePath); err != nil {
				fmt.Printf("\n" + red + "[PaoPaoGW REC]" + reset + "Failed to replace CSV file.\n")
				os.Rename(oldFilePath, currentFilePath)
			}
			if _, err := os.Stat(oldFilePath); err == nil {
				os.Remove(oldFilePath)
			}
			mutex.Unlock()
		}
		os.Exit(0)
	}
	//clash_yaml reload
	if reload {
		err := reloadYaml(apiURL, secret)
		if err != nil {
			fmt.Printf(red+"[PaoPaoGW Reload]"+reset+"ERR：%s\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n" + green + "[PaoPaoGW Reload]" + reset + "Yaml reload OK. \n")
		os.Exit(0)
	}
	//test_http_code
	if testProxy != "" {
		if testNodeURL == "" || testProxy == "" {
			fmt.Println("Please provide URL and HTTP proxy parameters")
			flag.Usage()
			os.Exit(1)
		}

		proxyURL, err := url.Parse(testProxy)
		if err != nil {
			fmt.Println("invalid proxy address:", err)
			os.Exit(1)
		}

		tr := &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Resolver: &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						dialer := net.Dialer{}
						proxyConn, err := dialer.Dial("tcp", proxyURL.Host)
						if err != nil {
							return nil, err
						}
						return proxyConn, nil
					},
				},
			}).DialContext,
		}

		client := &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		}

		resp, err := client.Get(testNodeURL)
		if err != nil {
			fmt.Println("Request error:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		fmt.Println("Node Check OK. HTTP CODE:", resp.StatusCode)
		os.Exit(0)
	}

	//clashapi ./ppgw -apiurl="http://10.10.10.3:9090" -secret="clashpass" -test_node_url="https://www.google.com" -ext_node="ong|Traffic|Expire| GB"
	//closeall conn
	if closeall {
		if secret == "" || apiURL == "" {
			os.Exit(1)
		}
		err := deleteConnections(apiURL, secret)
		if err != nil {
			fmt.Printf(red+"[PaoPaoGW Close]"+reset+"Unable to close connections %s：%v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if now_node {
		if secret == "" || apiURL == "" {
			os.Exit(1)
		}
		mode, _ := getMode(apiURL, secret)
		if mode != "global" {
			os.Exit(1)
		}
		_, now, err := getNodes(apiURL, secret)
		if err != nil {
			fmt.Print("Unable to get the now node.\n")
		} else {
			fmt.Print(now)
		}
		if now != "" {
			os.Exit(0)
		}
		os.Exit(1)
	}
	if apiURL != "" && secret != "" && spec_node != "" {
		err := selectNode(apiURL, secret, spec_node)
		if err != nil {
			fmt.Printf(red+"[PaoPaoGW SOCKS]"+reset+"Unable to select ppgwsocks ：%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n" + green + "[PaoPaoGW SOCKS]" + reset + "The ppgwsocks node selected.")
		// deleteConnections(apiURL, secret)
		os.Exit(0)
	}
	//fast_node
	if apiURL != "" {
		if secret == "" || testNodeURL == "" {
			os.Exit(1)
		}

		nodes, _, err := getNodes(apiURL, secret)
		if err != nil {
			fmt.Printf(red+"[PaoPaoGW Fast]"+reset+"Unable to get node list:%v\n", err)
			return
		}

		excludedNodes := parseExcludedNodes(extNodeStr)
		nodes = filterNodes(nodes, excludedNodes)

		pingResults := make([]PingResult, 0)
		waitdelaynum, err := strconv.Atoi(waitdelay)
		if err != nil {
			fmt.Println(err)
			return
		}
		for i := 0; i < len(nodes); i += 2 {
			go func(index int) {
				if index < len(nodes) {
					node1 := nodes[index]
					duration1, err1 := pingNode(apiURL, secret, node1.Node, testNodeURL)
					if err1 == nil {
						pingResults = append(pingResults, PingResult{Node: node1.Node, Duration: duration1})
					} else {
						fmt.Printf(red+"[PaoPaoGW Fast]"+reset+"Node %s:%v\n", node1.Node, err1)
						time.Sleep(time.Duration(1+waitdelaynum/1000) * time.Second)
					}
					if index+1 < len(nodes) {
						node2 := nodes[index+1]
						duration2, err2 := pingNode(apiURL, secret, node2.Node, testNodeURL)
						if err2 == nil {
							pingResults = append(pingResults, PingResult{Node: node2.Node, Duration: duration2})
						} else {
							fmt.Printf(red+"[PaoPaoGW Fast]"+reset+"Node %s：%v\n", node2.Node, err2)
							time.Sleep(time.Duration(1+waitdelaynum/1000) * time.Second)
						}
					}
				}

			}(i)
		}
		time.Sleep(time.Duration(waitdelaynum/1000+3) * time.Second)
		sort.Slice(pingResults, func(i, j int) bool {
			return pingResults[i].Duration < pingResults[j].Duration
		})

		printPingResults(pingResults)

		if len(pingResults) > 0 {
			fastestNode := pingResults[0].Node
			err := selectNode(apiURL, secret, fastestNode)
			if err != nil {
				fmt.Printf(red+"[PaoPaoGW Fast]"+reset+"Unable to select node %s：%v\n", fastestNode, err)
				os.Exit(1)
			}
			fmt.Printf("\n"+green+"[PaoPaoGW Fast]"+reset+"The fastest node selected:%s\n", fastestNode)
			// deleteConnections(apiURL, secret)
			os.Exit(0)
		} else {
			fmt.Println("\n" + red + "[PaoPaoGW Fast]" + reset + "All nodes failed !")
		}
		os.Exit(1)
	}
	//gen_host
	if rawURL != "" {
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			fmt.Printf("Failed to parse URL: %v\n", err)
			os.Exit(1)
		}
		host := parsedURL.Hostname()
		initDNS()
		ipString := nslookup(host)
		constructedURL := fmt.Sprintf("%s  %s", ipString, host)
		fmt.Println(constructedURL)
		os.Exit(0)
	}
	//wget
	if downURL != "" {
		downloader := NewDownloader(downURL, outputFile)
		err := downloader.Download()
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		} else {
			fmt.Println(green + "[PaoPaoGW Get]" + reset + "Download: OK!")
			os.Exit(0)
		}
	}
	//gen_cron
	if interval != "" && sleeptime != "" {
		result := parseSubtime(interval, sleeptime)
		fmt.Printf("%d", result)
		os.Exit(0)
	}
	//gen yaml hash
	if yamlhashFile != "" {
		content, err := os.ReadFile(yamlhashFile)
		if err != nil {
			fmt.Println("Cannot read", err)
			os.Exit(1)
		}

		var data map[interface{}]interface{}
		err = yaml.Unmarshal(content, &data)
		if err != nil {
			fmt.Println("Cannot Unmarshal YAML", err)
			os.Exit(1)
		}

		keys := make([]string, 0, len(data))
		for key := range data {
			keys = append(keys, fmt.Sprintf("%v", key))
		}
		sort.Strings(keys)

		var sb strings.Builder
		for _, key := range keys {
			value := fmt.Sprintf("%v", data[key])
			sb.WriteString(key)
			sb.WriteString(value)
		}

		hash := fnv.New32a()
		hash.Write([]byte(sb.String()))
		fmt.Printf("%x", hash.Sum32())
		os.Exit(0)
	}
	//dns_burn
	if dnslist != "" {
		if inputFile == "" {
			fmt.Println("Please provide an input YAML file using the -input flag")
		}

		data, err := os.ReadFile(inputFile)
		if err != nil {
			fmt.Println("Error reading input file:", err)
		}

		var config map[string]interface{}
		if err := yaml.Unmarshal(data, &config); err != nil {
			fmt.Println("Error unmarshalling YAML: ", err)
		}

		proxies, ok := config["proxies"].([]interface{})
		if !ok {
			fmt.Println("No 'proxies' found in the YAML file")
		}
		dnsServers := strings.Split(dnslist, ",")

		var newProxies []interface{}
		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, proxy := range proxies {
			p, ok := proxy.(map[interface{}]interface{})
			if !ok {
				fmt.Printf("Skipping invalid proxy: %+v\n", proxy)
				continue
			}

			server, ok := p["server"].(string)
			if !ok {
				fmt.Printf("Skipping proxy without a 'server' field: %+v\n", p)
				continue
			}

			wg.Add(1)
			go func(name, server string) {
				defer wg.Done()

				serverList := dnsRes(server, dnsServers)

				mu.Lock()
				defer mu.Unlock()

				for _, serverAddr := range serverList {
					newProxy := make(map[interface{}]interface{})
					for key, value := range p {
						newProxy[key] = value
					}
					newProxy["name"] = fmt.Sprintf("%s-%s", name, serverAddr)
					newProxy["server"] = serverAddr
					newProxies = append(newProxies, newProxy)
				}
			}(p["name"].(string), server)
		}

		wg.Wait()

		config["proxies"] = append(proxies, newProxies...)

		newData, err := yaml.Marshal(&config)
		if err != nil {
			fmt.Println("Error marshalling new YAML:", err)
		}

		if err := os.WriteFile(outputFile, newData, 0644); err != nil {
			fmt.Println("Error writing output file: ", err)
		}

		fmt.Printf("New configuration written to %s\n", outputFile)

		os.Exit(0)
	}
	//combine yaml
	if inputFiles != nil {
		result := make(map[interface{}]interface{})

		for _, inputFile := range inputFiles {
			data, err := os.ReadFile(inputFile)
			if err != nil {
				fmt.Println("Failed to read file : ", inputFile, err)
				os.Exit(1)
			}

			m := make(map[interface{}]interface{})
			err = yaml.Unmarshal(data, &m)
			if err != nil {
				fmt.Println("Failed to unmarshal YAML from file : ", inputFile, err)
				os.Exit(1)
			}

			for k, v := range m {
				result[k] = v
			}
		}

		data, err := yaml.Marshal(result)
		if err != nil {
			fmt.Println("Failed to marshal result to YAML: ", err)
			os.Exit(1)
		}

		err = os.WriteFile(outputFile, data, 0644)
		if err != nil {
			fmt.Println("Failed to write result to file : ", outputFile, err)
			os.Exit(1)
		}

		fmt.Printf("Merged YAML written to %s\n", outputFile)
		os.Exit(0)
	}
	flag.CommandLine.Usage()
}

// net rec func
func (d DomainInfoList) Len() int {
	return len(d)
}

func (d DomainInfoList) Less(i, j int) bool {
	return d[i].Download+d[i].Upload > d[j].Download+d[j].Upload
}

func (d DomainInfoList) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.3fGB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.3fMB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.3fKB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
func dnsRes(domain string, dnsServers []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	ipSet := make(map[string]struct{})
	for _, dnsServer := range dnsServers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			ipAddrs, err := QueryARecords(context.Background(), &domain, server)
			if err == nil {
				mu.Lock()
				for _, ipAddr := range ipAddrs {
					ipSet[ipAddr.String()] = struct{}{}
				}
				mu.Unlock()
			}
		}(dnsServer)
	}

	wg.Wait()

	uniqueIPs := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		uniqueIPs = append(uniqueIPs, ip)
	}

	return uniqueIPs
}

func QueryARecords(ctx context.Context, domain *string, dnsServer string) ([]net.IP, error) {
	dnsResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "udp", dnsServer)
		},
	}

	ips, err := dnsResolver.LookupIP(ctx, "ip4", *domain)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records found for domain: %s", *domain)
	}

	return ips, nil
}

func NewDownloader(url, outputFile string) *Downloader {
	return &Downloader{
		URL:        url,
		OutputFile: outputFile,
		UserAgent:  "ClashforWindows/clash-verge/Clash/clash",
		Timeout:    10 * time.Second,
	}
}

func (d *Downloader) Download() error {
	client := d.createClient()
	req, err := http.NewRequest("GET", d.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", d.UserAgent)

	host := req.URL.Hostname()
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf(red+"[PaoPaoGW Get]"+reset+host+"failed to perform DNS lookup: %v", err)
	}
	fmt.Println(orange+"[PaoPaoGW Get]"+reset+"HOST:"+host+" IP:", strings.Join(addrs, ", "))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(red+"[PaoPaoGW Get]"+reset+"request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf(red+"[PaoPaoGW Get]"+reset+host+" request failed with status code %d", resp.StatusCode)
	}

	finalURL := resp.Request.URL.String()
	fmt.Println(orange+"[PaoPaoGW Get]"+reset+"URL:", finalURL)

	file, err := os.Create(d.OutputFile)
	if err != nil {
		return fmt.Errorf(red+"[PaoPaoGW Get]"+reset+"failed to create output file: %v", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf(red+"[PaoPaoGW Get]"+reset+host+" download failed: %v", err)
	}

	return nil
}

func (d *Downloader) createClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   d.Timeout,
	}
}

func nslookup(domain string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		os.Exit(1)
	}
	if len(r) == 0 {
		os.Exit(1)
	}
	ip := r[0].IP.String()
	return ip
}

func parseSubtime(subtime, sleeptime string) int {
	duration := 86400
	if subtime != "" {
		if strings.HasSuffix(subtime, "d") {
			nStr := strings.TrimSuffix(subtime, "d")
			n, err := strconv.Atoi(nStr)
			if err == nil {
				duration = n * 86400
			}
		} else if strings.HasSuffix(subtime, "h") {
			nStr := strings.TrimSuffix(subtime, "h")
			n, err := strconv.Atoi(nStr)
			if err == nil {
				duration = n * 3600
			}
		} else if strings.HasSuffix(subtime, "m") {
			nStr := strings.TrimSuffix(subtime, "m")
			n, err := strconv.Atoi(nStr)
			if err == nil {
				duration = n * 60
			}
		}
	}
	sleeptimeInt, err := strconv.Atoi(sleeptime)
	if err != nil {
		sleeptimeInt = 30
	}
	result := duration / sleeptimeInt
	return result
}

func initDNS() {
	if server != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, net.JoinHostPort(server, strconv.Itoa(port)))
			},
		}
	} else {
		resolver = net.DefaultResolver
	}
}

func (i *inputFlags) String() string {
	return fmt.Sprint(*i)
}

func (i *inputFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// clashapi
func printPingResults(results []PingResult) {
	for _, result := range results {
		fmt.Printf("| %-60s | %-10s |\n", result.Node, result.Duration.String())
	}
}

func getNodes(apiURL, secret string) ([]ClashNode, string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	req, err := http.NewRequest("GET", apiURL+"/proxies", nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	var apiResponse ClashAPIResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		return nil, "", fmt.Errorf(resp.Status + ":" + err.Error())

	}
	nodes := make([]ClashNode, 0, len(apiResponse.Proxies))
	for _, node := range apiResponse.Proxies {
		if !isSystemNode(node.Type) {
			nodes = append(nodes, node)
		}
	}
	globalProxy, ok := apiResponse.Proxies["GLOBAL"]
	if ok {
		return nodes, globalProxy.Now, nil
	}
	return nodes, "", nil
}

func getMode(apiURL, secret string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	req, err := http.NewRequest("GET", apiURL+"/configs", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var configResponse ConfigResponse
	err = json.Unmarshal(body, &configResponse)
	if err != nil {
		return "", fmt.Errorf(resp.Status + ":" + err.Error())
	}

	return configResponse.Mode, nil
}

func parseExcludedNodes(extNodeStr string) []string {
	if extNodeStr == "" {
		return nil
	}

	excludedNodes := strings.Split(extNodeStr, "|")
	return excludedNodes
}

func filterNodes(nodes []ClashNode, excludedNodes []string) []ClashNode {
	filteredNodes := make([]ClashNode, 0)

	for _, node := range nodes {
		if !containsExcludedKeyword(node.Node, excludedNodes) && !isSystemNode(node.Node) {
			filteredNodes = append(filteredNodes, node)
		}
	}

	return filteredNodes
}

func isSystemNode(nodeName string) bool {
	systemNodes := []string{"REJECT", "DIRECT", "GLOBAL", "SELECTOR", "RELAY", "FALLBACK", "URLTEST", "LOADBALANCE", "UNKNOWN"}
	nodeName = strings.ToUpper(nodeName)
	for _, sysNode := range systemNodes {
		if nodeName == sysNode {
			return true
		}
	}

	return false
}

func containsExcludedKeyword(nodeName string, excludedNodes []string) bool {
	for _, keyword := range excludedNodes {
		if strings.Contains(nodeName, keyword) {
			return true
		}
	}
	return false
}

func systemLoadDealy() int64 {
	startTime := time.Now()
	cmd := exec.Command("ps")
	err := cmd.Run()
	if err != nil {
		return 10000
	}
	executionTime := time.Since(startTime).Milliseconds()
	return executionTime
}

func pingNode(apiURL, secret, nodeName, testNodeURL string) (time.Duration, error) {
	delay := systemLoadDealy()
	if delay > int64(maxSystemCommandDelay) {
		return 0, fmt.Errorf("High CPU load: %d", delay)
	}

	client := &http.Client{}

	requestURL := fmt.Sprintf("%s/proxies/%s/delay?timeout=%s&url=%s", apiURL, nodeName, waitdelay, testNodeURL)
	// fmt.Println(requestURL)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var pingResp PingResponse
		err = json.NewDecoder(resp.Body).Decode(&pingResp)
		if err != nil {
			return 0, err
		}

		if pingResp.Delay > 0 {
			return time.Duration(pingResp.Delay) * time.Millisecond, nil
		}

		return 0, fmt.Errorf("The delay value does not exist")
	}

	return 0, fmt.Errorf("%s", resp.Status)
}

func selectNode(apiURL, secret, nodeName string) error {
	setGlobalMode(apiURL, secret)
	client := &http.Client{}

	data := []byte(fmt.Sprintf(`{"name":"%s"}`, nodeName))

	req, err := http.NewRequest("PUT", apiURL+"/proxies/GLOBAL", strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("The node selection request failed：%s", resp.Status)
}

func reloadYaml(apiURL, secret string) error {
	client := &http.Client{}
	data := []byte(fmt.Sprintf(`{"path":"/tmp/clash.yaml"}`))
	req, err := http.NewRequest("PUT", apiURL+"/configs", strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to reload configuration: %s, unable to read response body", resp.Status)
	}

	errorMessage := fmt.Sprintf("Failed to reload configuration: %s, response body: %s", resp.Status, string(bodyBytes))
	return fmt.Errorf(errorMessage)
}

func setGlobalMode(apiURL, secret string) error {
	url := fmt.Sprintf("%s/configs", apiURL)
	payload := []byte(`{"mode":"Global"}`)

	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", secret))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("Failed to set Global mode, response status code	：%d", resp.StatusCode)
}

func deleteConnections(apiURL, secret string) error {
	url := fmt.Sprintf("%s/connections", apiURL)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", secret))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("Failed to delete connections, response status code: %d", resp.StatusCode)
}
