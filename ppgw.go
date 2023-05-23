package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	server       string
	domain       string
	rawURL       string
	port         int
	resolver     *net.Resolver
	inputFiles   inputFlags
	outputFile   string
	yamlhashFile string
	interval     string
	apiURL       string
	secret       string
	testNodeURL  string
	extNodeStr   string
	testProxy    string
)

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

func nslookup(domain string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return err.Error()
	}
	if len(r) == 0 {
		return "no IP addresses found for the domain"
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
func main() {

	flag.Var(&inputFiles, "input", "Input YAML files")
	flag.StringVar(&outputFile, "output", "output.yaml", "Output YAML file")
	flag.StringVar(&yamlhashFile, "yamlhashFile", "", "Hash YAML file")
	flag.StringVar(&domain, "domain", "", "domain")
	flag.StringVar(&rawURL, "rawURL", "", "rawURL")
	flag.StringVar(&server, "server", "", "DNS server to use")
	flag.StringVar(&interval, "interval", "", "sub interval")
	flag.StringVar(&testProxy, "testProxy", "", "http testProxy")
	flag.IntVar(&port, "port", 53, "DNS port")

	//clashapi
	flag.StringVar(&apiURL, "apiurl", "", "Clash API")
	flag.StringVar(&secret, "secret", "", "Clash secret")
	flag.StringVar(&testNodeURL, "test_node_url", "", "test_node_url")
	flag.StringVar(&extNodeStr, "ext_node", "", "ext_node")

	flag.Parse()

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
	if apiURL != "" {
		if secret == "" || testNodeURL == "" {
			os.Exit(1)
		}

		nodes, err := getNodes(apiURL, secret)
		if err != nil {
			fmt.Printf("Unable to get node list:%v\n", err)
			return
		}

		excludedNodes := parseExcludedNodes(extNodeStr)
		nodes = filterNodes(nodes, excludedNodes)

		pingResults := make([]PingResult, 0)
		for i := 0; i < len(nodes); i += 2 {
			go func(index int) {
				if index < len(nodes) {
					node1 := nodes[index]
					duration1, err1 := pingNode(apiURL, secret, node1.Node, testNodeURL)
					if err1 == nil {
						pingResults = append(pingResults, PingResult{Node: node1.Node, Duration: duration1})
					} else {
						fmt.Printf("Unable to test connection speed for node %s:%v\n", node1.Node, err1)
					}
					if index+1 < len(nodes) {
						node2 := nodes[index+1]
						duration2, err2 := pingNode(apiURL, secret, node2.Node, testNodeURL)
						if err2 == nil {
							pingResults = append(pingResults, PingResult{Node: node2.Node, Duration: duration2})
						} else {
							fmt.Printf("Unable to test the connection speed of node %s：%v\n", node2.Node, err2)
						}
					}
				}
			}(i)
		}

		time.Sleep(3 * time.Second)

		sort.Slice(pingResults, func(i, j int) bool {
			return pingResults[i].Duration < pingResults[j].Duration
		})

		printPingResults(pingResults)

		if len(pingResults) > 0 {
			fastestNode := pingResults[0].Node
			err := selectNode(apiURL, secret, fastestNode)
			if err != nil {
				fmt.Printf("Unable to select node %s：%v\n", fastestNode, err)
				return
			}
			fmt.Printf("\nThe fastest node selected:%s\n", fastestNode)
		} else {
			fmt.Println("\nThere are no nodes available")
		}
		os.Exit(0)
	}

	if rawURL != "" {
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			fmt.Printf("Failed to parse URL: %v\n", err)
			os.Exit(0)
		}
		host := parsedURL.Hostname()
		initDNS()
		ipString := nslookup(host)
		constructedURL := fmt.Sprintf("%s  %s", ipString, host)
		fmt.Println(constructedURL)
		os.Exit(0)
	}
	if domain != "" {
		initDNS()
		fmt.Print(nslookup(domain))
		os.Exit(0)
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
			log.Fatalf("Cannot read %v", err)
		}

		var data map[interface{}]interface{}
		err = yaml.Unmarshal(content, &data)
		if err != nil {
			log.Fatalf("Cannot Unmarshal YAML：%v", err)
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

		hash := md5.Sum([]byte(sb.String()))
		fmt.Printf("%x", hash)
		os.Exit(0)
	}
	result := make(map[interface{}]interface{})

	for _, inputFile := range inputFiles {
		data, err := ioutil.ReadFile(inputFile)
		if err != nil {
			log.Fatalf("Failed to read file %s: %v", inputFile, err)
		}

		m := make(map[interface{}]interface{})
		err = yaml.Unmarshal(data, &m)
		if err != nil {
			log.Fatalf("Failed to unmarshal YAML from file %s: %v", inputFile, err)
		}

		for k, v := range m {
			result[k] = v
		}
	}

	data, err := yaml.Marshal(result)
	if err != nil {
		log.Fatalf("Failed to marshal result to YAML: %v", err)
	}

	err = ioutil.WriteFile(outputFile, data, 0644)
	if err != nil {
		log.Fatalf("Failed to write result to file %s: %v", outputFile, err)
	}

	fmt.Printf("Merged YAML written to %s\n", outputFile)
}

type inputFlags []string

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
		nodes = append(nodes, node)
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
	systemNodes := []string{"REJECT", "DIRECT", "GLOBAL"}
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

func pingNode(apiURL, secret, nodeName, testNodeURL string) (time.Duration, error) {
	client := &http.Client{}

	requestURL := fmt.Sprintf("%s/proxies/%s/delay?timeout=3000&url=%s", apiURL, nodeName, testNodeURL)

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

	return 0, fmt.Errorf("The node latency request failed：%s", resp.Status)
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
