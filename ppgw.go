package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
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
	outputFile            string
	yamlhashFile          string
	interval              string
	apiURL                string
	secret                string
	testNodeURL           string
	extNodeStr            string
	testProxy             string
	reload                bool
	closeall              bool
)

var orange = "\033[38;5;208m"
var green = "\033[32m"
var red = "\033[31m"
var reset = "\033[0m"

type inputFlags []string

type ClashNode struct {
	Node  string `json:"name"`
	Proxy string `json:"type"`
}

type ClashAPIResponse struct {
	Proxies map[string]ClashNode `json:"proxies"`
}

type PingResult struct {
	Node     string
	Duration time.Duration
}

type PingResponse struct {
	Delay     int `json:"delay"`
	MeanDelay int `json:"meanDelay"`
}

type Downloader struct {
	URL        string
	OutputFile string
	UserAgent  string
	Timeout    time.Duration
}

func main() {

	flag.Var(&inputFiles, "input", "Input YAML files")
	flag.StringVar(&outputFile, "output", "output.yaml", "Output YAML file")
	flag.StringVar(&yamlhashFile, "yamlhashFile", "", "Hash YAML file")
	flag.StringVar(&domain, "domain", "", "domain")
	flag.StringVar(&rawURL, "rawURL", "", "rawURL")
	flag.StringVar(&downURL, "downURL", "", "downURL")
	flag.StringVar(&server, "server", "", "DNS server to use")
	flag.StringVar(&interval, "interval", "", "sub interval")
	flag.StringVar(&testProxy, "testProxy", "", "http testProxy")
	flag.IntVar(&port, "port", 53, "DNS port")

	//clashapi
	flag.StringVar(&apiURL, "apiurl", "", "Clash API")
	flag.StringVar(&secret, "secret", "", "Clash secret")
	flag.StringVar(&testNodeURL, "test_node_url", "", "test_node_url")
	flag.StringVar(&extNodeStr, "ext_node", "", "ext_node")
	flag.StringVar(&waitdelay, "waitdelay", "1000", "node delay")
	flag.IntVar(&maxSystemCommandDelay, "cpudelay", 300, "CPU delay")
	flag.BoolVar(&reload, "reload", false, "reload yaml")
	flag.BoolVar(&closeall, "closeall", false, "close all connections.")

	flag.Parse()
	if reload {
		err := reloadYaml(apiURL, secret)
		if err != nil {
			fmt.Printf(red+"[PaoPaoGW Reload]"+reset+"ERR：%s\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n" + green + "[PaoPaoGW Reload]" + reset + "Yaml reload OK. \n")
		os.Exit(0)
	}
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
	if apiURL != "" {
		if secret == "" || testNodeURL == "" {
			os.Exit(1)
		}

		nodes, err := getNodes(apiURL, secret)
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
			}
			fmt.Printf("\n"+green+"[PaoPaoGW Fast]"+reset+"The fastest node selected:%s\n", fastestNode)
			deleteConnections(apiURL, secret)
			os.Exit(0)
		} else {
			fmt.Println("\n" + red + "[PaoPaoGW Fast]" + reset + "All nodes failed !")
		}
		os.Exit(1)
	}

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
	if interval != "" {
		err := updateCrontab(interval)
		if err != nil {
			fmt.Printf("Error updating crontab: %v\n", err)
			return
		}
		fmt.Println("Crontab updated successfully.")
		os.Exit(0)
	}

	if yamlhashFile != "" {
		content, err := ioutil.ReadFile(yamlhashFile)
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
	if inputFiles != nil {
		result := make(map[interface{}]interface{})

		for _, inputFile := range inputFiles {
			data, err := ioutil.ReadFile(inputFile)
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

		err = ioutil.WriteFile(outputFile, data, 0644)
		if err != nil {
			fmt.Println("Failed to write result to file : ", outputFile, err)
			os.Exit(1)
		}

		fmt.Printf("Merged YAML written to %s\n", outputFile)
		os.Exit(0)
	}
	flag.CommandLine.Usage()
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
	fmt.Println(orange+"[PaoPaoGW Get]"+reset+host+" IP:", strings.Join(addrs, ", "))

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
func updateCrontab(interval string) error {
	interval = strings.ToLower(interval)
	cronExpression, err := convertToCronExpression(interval)
	if err != nil {
		return err
	}
	return writeCrontab(cronExpression)
}

func convertToCronExpression(interval string) (string, error) {
	lastChar := interval[len(interval)-1]
	durationPart := interval[:len(interval)-1]
	var totalMinutes int

	switch lastChar {
	case 'm':
		duration, err := strconv.Atoi(durationPart)
		if err != nil {
			return "", err
		}
		totalMinutes = duration
	case 'h':
		duration, err := strconv.Atoi(durationPart)
		if err != nil {
			return "", err
		}
		totalMinutes = duration * 60
	case 'd':
		duration, err := strconv.Atoi(durationPart)
		if err != nil {
			return "", err
		}
		totalMinutes = duration * 24 * 60
	default:
		return "", fmt.Errorf("invalid time interval")
	}

	switch {
	case totalMinutes >= 24*60:
		days := totalMinutes / (24 * 60)
		return fmt.Sprintf("0 0 */%d * *", days), nil
	case totalMinutes > 60:
		hours := totalMinutes / 60
		return fmt.Sprintf("0 */%d * * *", hours), nil
	case totalMinutes > 0:
		return fmt.Sprintf("*/%d * * * *", totalMinutes), nil
	default:
		return "", fmt.Errorf("invalid time interval")
	}
}

func writeCrontab(cronExpression string) error {
	filePath := "/etc/crontabs/root"
	err := ioutil.WriteFile(filePath, []byte(""), 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filePath, []byte(cronExpression+" /usr/bin/cron.sh\n"), 0644)
	if err != nil {
		return err
	}
	return nil
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

func getNodes(apiURL, secret string) ([]ClashNode, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", apiURL+"/proxies", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResponse ClashAPIResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		return nil, err
	}

	nodes := make([]ClashNode, 0, len(apiResponse.Proxies))
	for _, node := range apiResponse.Proxies {
		if !isSystemNode(node.Proxy) {
			nodes = append(nodes, node)
		}
	}

	return nodes, nil
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
		fmt.Printf(red+"[PaoPaoGW Fast]"+reset+"Node %s：%v\n", nodeName, "High CPU load:", delay)
		os.Exit(2)
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

	bodyBytes, err := ioutil.ReadAll(resp.Body)
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
