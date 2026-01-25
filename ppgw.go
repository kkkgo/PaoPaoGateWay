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
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	input_cleanday        string
	ppsubFile             string
	dnsBurn               bool
	exDNS                 string
	healthCheckFile       string
	ipv6Enabled           bool
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
	Headers    http.Header
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
	Domain     string    `json:"domain"`
	Download   int64     `json:"download"`
	Upload     int64     `json:"upload"`
	Total      int64     `json:"total"`
	ClientIPs  []string  `json:"clientIPs"`
	LastUpdate time.Time `json:"lastUpdate"`
}

type DomainInfoList []DomainInfo

type LastConnectionInfo struct {
	LastDownloadTotal int64
	LastUploadTotal   int64
}
type GlobalMonitor struct {
	Enable         bool   `json:"enable"`
	URL            string `json:"url"`
	Retries        int    `json:"retries"`
	ExpectedStatus string `json:"expected_status"`
}
type PPSubConfig struct {
	Version       string        `json:"version"`
	ExportedAt    string        `json:"exported_at"`
	GlobalMonitor GlobalMonitor `json:"global_monitor,omitempty"`
	Subs          []SubProvider `json:"subs"`
	NodeGroups    []NodeGroup   `json:"node-groups"`
	Rules         []RuleSet     `json:"rules"`
}

type SubProvider struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	IsForced bool   `json:"isforced,omitempty"`
}

type NodeGroup struct {
	Name            string   `json:"name"`
	Keywords        []string `json:"keywords"`
	ExcludeKeywords []string `json:"exclude_keywords"`
	Subs            []string `json:"subs"`
	Include         []string `json:"include,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	SpeedtestURL    string   `json:"speedtest_url,omitempty"`
	Interval        int      `json:"interval,omitempty"`
	UsePreProxy     bool     `json:"use_pre_proxy,omitempty"`
	PreProxyGroup   string   `json:"pre_proxy_group,omitempty"`
}

type RuleSet struct {
	Priority int      `json:"priority"`
	Type     string   `json:"type,omitempty"`
	Name     string   `json:"name,omitempty"`
	URL      string   `json:"url,omitempty"`
	Behavior string   `json:"behavior,omitempty"`
	Interval int      `json:"interval,omitempty"`
	FixRule  []string `json:"fixrule,omitempty"`
	IsForced bool     `json:"isforced,omitempty"`
	Format   string   `json:"format,omitempty"`
	Proxy    string   `json:"proxy,omitempty"`
}

type ClashConfig struct {
	Proxies        []map[string]interface{} `yaml:"proxies"`
	ProxyGroups    []map[string]interface{} `yaml:"proxy-groups"`
	ProxyProviders map[string]interface{}   `yaml:"proxy-providers,omitempty"`
	RuleProviders  map[string]interface{}   `yaml:"rule-providers,omitempty"`
	Rules          []string                 `yaml:"rules"`
	Mode           string                   `yaml:"mode,omitempty"`
}
type SubscriptionUserInfo struct {
	Total    int64
	Upload   int64
	Download int64
	Expire   int64
}

func dropPrivileges() error {
	if err := syscall.Setgid(65534); err != nil {
		return fmt.Errorf("setgid failed: %v", err)
	}

	if err := syscall.Setuid(65534); err != nil {
		return fmt.Errorf("setuid failed: %v", err)
	}
	return nil
}
func main() {
	backupWsURL := os.Getenv("backipws")
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
	flag.StringVar(&input_cleanday, "input_cleanday", "", "input clean day (1-31)")
	flag.StringVar(&ppsubFile, "ppsub", "", "PPSub JSON config file")
	flag.BoolVar(&dnsBurn, "dns_burn", false, "Enable DNS burn mode")
	flag.StringVar(&exDNS, "ex_dns", "", "Extra DNS servers (comma separated)")
	flag.StringVar(&healthCheckFile, "healthcheck", "", "Health check config file")
	flag.Parse()

	ipv6Enabled = checkIPv6Support()

	// health check logic
	if healthCheckFile != "" {
		configData, err := os.ReadFile(healthCheckFile)
		if err != nil {
			fmt.Printf(red+"[PaoPaoGW Health]Failed to read config file: %v\n"+reset, err)
			os.Exit(255)
		}

		var config PPSubConfig
		if err := json.Unmarshal(configData, &config); err != nil {
			fmt.Printf(red+"[PaoPaoGW Health]Failed to parse config file: %v\n"+reset, err)
			os.Exit(255)
		}

		monitor := config.GlobalMonitor

		if !monitor.Enable {
			os.Exit(0)
		}

		targetURL := monitor.URL
		if targetURL == "" {
			targetURL = "https://www.youtube.com/generate_204"
		}

		retries := monitor.Retries
		if retries <= 0 {
			retries = 3
		}

		expectedStatus := monitor.ExpectedStatus
		if expectedStatus == "" {
			expectedStatus = "0"
		}
		localProxy := "socks5://127.0.0.1:1080"
		for i := 0; i <= retries; i++ {
			success, code, err := checkURLConnectivity(targetURL, localProxy, expectedStatus)
			if err != nil {
				fmt.Printf(red+"[PaoPaoGW Health] %s failed: %v\n"+reset, targetURL, err)
			} else if success {
				fmt.Printf(green+"[PaoPaoGW Health] %s Success HTTP CODE: %d\n"+reset, targetURL, code)
				os.Exit(0)
			} else {
				fmt.Printf(red+"[PaoPaoGW Health] Failed. %s CODE:[%d], Need: %s\n"+reset, targetURL, code, expectedStatus)
			}

			if i == retries {
				fmt.Printf(red + "[PaoPaoGW Health] Max retries reached. Exiting.\n" + reset)
				os.Exit(255)
			}
			time.Sleep(1 * time.Second)
		}
	}
	// net_rec
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

		type ConnectionHistory struct {
			LastDownload int64
			LastUpload   int64
			LastSeen     time.Time
		}
		connectionHistory := make(map[string]*ConnectionHistory)

		type BackupIPMapping struct {
			Destination string
			RealIP      string
			UpdateTime  time.Time
		}
		backupIPMap := make(map[string]BackupIPMapping)
		var backupMapMutex sync.RWMutex

		var domainMutex sync.RWMutex
		var historyMutex sync.RWMutex

		type IPUpdateTask struct {
			Domain string
			RealIP string
		}
		ipUpdateChan := make(chan IPUpdateTask, 1000)
		recPath := "/etc/config/clash/clash-dashboard/rec_data/" + reckey
		go func() {
			for task := range ipUpdateChan {
				domainMutex.Lock()
				if domainInfo, exists := domainInfoMap[task.Domain]; exists {
					hasLocalhost := false
					hasRealIP := false
					localhostIndex := -1

					for i, ip := range domainInfo.ClientIPs {
						if ip == "127.0.0.1" {
							hasLocalhost = true
							localhostIndex = i
						}
						if ip == task.RealIP {
							hasRealIP = true
						}
					}

					if hasLocalhost && hasRealIP {
						domainInfo.ClientIPs = append(
							domainInfo.ClientIPs[:localhostIndex],
							domainInfo.ClientIPs[localhostIndex+1:]...,
						)
					} else if hasLocalhost && !hasRealIP {
						domainInfo.ClientIPs[localhostIndex] = task.RealIP
					} else if !hasRealIP {
						domainInfo.ClientIPs = append(domainInfo.ClientIPs, task.RealIP)
					}
				}
				domainMutex.Unlock()
			}
		}()

		if backupWsURL != "" {
			fmt.Printf(green + "[PaoPaoGW REC]" + reset + "Backup WS enabled.\n")
			go func() {
				for {
					conn, _, err := websocket.Dial(ctx, backupWsURL, nil)
					if err != nil {
						fmt.Printf(red + "[PaoPaoGW REC Backup]" + reset + "Failed to dial backup WebSocket.\n")
						time.Sleep(5 * time.Second)
						continue
					}
					conn.SetReadLimit(10 * 1024 * 1024)

					for {
						var connectionInfo ConnectionInfo
						err := wsjson.Read(ctx, conn, &connectionInfo)
						if err != nil {
							fmt.Printf(red + "[PaoPaoGW REC Backup]" + reset + "Failed to read backup WebSocket.\n")
							conn.Close(websocket.StatusInternalError, "PPGW NET_REC BACKUP ERR")
							break
						}

						now := time.Now()

						backupMapMutex.Lock()
						for _, connection := range connectionInfo.Connections {
							dest := connection.Metadata.Host
							if dest == "" {
								dest = connection.Metadata.DestinationIP
							}

							sourceIP := connection.Metadata.SourceIP
							if sourceIP == "" {
								sourceIP = "127.0.0.1"
							}

							if isValidDestination(dest) && sourceIP != "127.0.0.1" {
								backupIPMap[dest] = BackupIPMapping{
									Destination: dest,
									RealIP:      sourceIP,
									UpdateTime:  now,
								}

								select {
								case ipUpdateChan <- IPUpdateTask{Domain: dest, RealIP: sourceIP}:
								default:
								}
							}
						}

						if len(backupIPMap) > max_rec*2 {
							cutoff := now.Add(-30 * time.Second)
							for dest, mapping := range backupIPMap {
								if mapping.UpdateTime.Before(cutoff) {
									delete(backupIPMap, dest)
								}
							}
						}
						backupMapMutex.Unlock()
					}
				}
			}()
		}

		go func() {
			for {
				conn, _, err := websocket.Dial(ctx, wsURL, nil)
				if err != nil {
					fmt.Printf("\n" + red + "[PaoPaoGW REC]" + reset + "Failed to dial WebSocket.\n")
					time.Sleep(5 * time.Second)
					continue
				}
				conn.SetReadLimit(10 * 1024 * 1024)

				for {
					var connectionInfo ConnectionInfo
					err := wsjson.Read(ctx, conn, &connectionInfo)
					if err != nil {
						fmt.Printf("\n" + red + "[PaoPaoGW REC]" + reset + "Failed to read WebSocket message.\n")
						conn.Close(websocket.StatusInternalError, "PPGW NET_REC ERR")
						break
					}

					now := time.Now()

					type DomainUpdate struct {
						Domain   string
						Download int64
						Upload   int64
						SourceIP string
					}
					updates := make([]DomainUpdate, 0, len(connectionInfo.Connections))

					historyMutex.Lock()
					activeConnIDs := make(map[string]bool, len(connectionInfo.Connections))

					for _, connection := range connectionInfo.Connections {
						destination := connection.Metadata.Host
						if destination == "" {
							destination = connection.Metadata.DestinationIP
						}

						if !isValidDestination(destination) {
							continue
						}

						activeConnIDs[connection.ID] = true
						sourceIP := connection.Metadata.SourceIP
						if sourceIP == "" {
							sourceIP = "127.0.0.1"
						}

						if sourceIP == "127.0.0.1" && backupWsURL != "" {
							backupMapMutex.RLock()
							if mapping, exists := backupIPMap[destination]; exists {
								if time.Since(mapping.UpdateTime) < 5*time.Second {
									sourceIP = mapping.RealIP
								}
							}
							backupMapMutex.RUnlock()
						}

						currentDownload := int64(connection.Download)
						currentUpload := int64(connection.Upload)

						history, exists := connectionHistory[connection.ID]
						if !exists {
							connectionHistory[connection.ID] = &ConnectionHistory{
								LastDownload: currentDownload,
								LastUpload:   currentUpload,
								LastSeen:     now,
							}

							if currentDownload > 0 || currentUpload > 0 {
								updates = append(updates, DomainUpdate{
									Domain:   destination,
									Download: currentDownload,
									Upload:   currentUpload,
									SourceIP: sourceIP,
								})
							}
						} else {
							downloadDelta := currentDownload - history.LastDownload
							uploadDelta := currentUpload - history.LastUpload

							history.LastDownload = currentDownload
							history.LastUpload = currentUpload
							history.LastSeen = now

							if downloadDelta > 0 || uploadDelta > 0 {
								updates = append(updates, DomainUpdate{
									Domain:   destination,
									Download: downloadDelta,
									Upload:   uploadDelta,
									SourceIP: sourceIP,
								})
							}
						}
					}
					historyMutex.Unlock()

					if len(updates) > 0 {
						domainMutex.Lock()
						for _, update := range updates {
							domainInfo, ok := domainInfoMap[update.Domain]
							if !ok {
								clientIPs := []string{}
								if update.SourceIP != "127.0.0.1" {
									clientIPs = []string{update.SourceIP}
								} else {
									clientIPs = []string{update.SourceIP}
								}

								domainInfoMap[update.Domain] = &DomainInfo{
									Domain:     update.Domain,
									Download:   update.Download,
									Upload:     update.Upload,
									Total:      update.Download + update.Upload,
									ClientIPs:  clientIPs,
									LastUpdate: now,
								}
							} else {
								hasUpdate := false
								if update.Download > 0 {
									domainInfo.Download += update.Download
									hasUpdate = true
								}
								if update.Upload > 0 {
									domainInfo.Upload += update.Upload
									hasUpdate = true
								}
								if hasUpdate {
									domainInfo.Total = domainInfo.Download + domainInfo.Upload
									domainInfo.LastUpdate = now
								}

								if update.SourceIP != "127.0.0.1" {
									ipExists := false
									hasLocalhost := false
									localhostIndex := -1

									for i, existingIP := range domainInfo.ClientIPs {
										if existingIP == update.SourceIP {
											ipExists = true
										}
										if existingIP == "127.0.0.1" {
											hasLocalhost = true
											localhostIndex = i
										}
									}

									if hasLocalhost {
										domainInfo.ClientIPs = append(
											domainInfo.ClientIPs[:localhostIndex],
											domainInfo.ClientIPs[localhostIndex+1:]...,
										)
										ipExists = false
										for _, existingIP := range domainInfo.ClientIPs {
											if existingIP == update.SourceIP {
												ipExists = true
												break
											}
										}
									}

									if !ipExists {
										domainInfo.ClientIPs = append(domainInfo.ClientIPs, update.SourceIP)
									}
								} else if len(domainInfo.ClientIPs) == 0 {
									domainInfo.ClientIPs = []string{update.SourceIP}
								}
							}
						}
						domainMutex.Unlock()
					}

					historyMutex.Lock()
					if len(connectionHistory) > max_rec*5 {
						cutoffTime := now.Add(-30 * time.Second)
						for id, history := range connectionHistory {
							if history.LastSeen.Before(cutoffTime) && !activeConnIDs[id] {
								delete(connectionHistory, id)
							}
						}
					}
					historyMutex.Unlock()

					domainMutex.Lock()
					if len(domainInfoMap) > max_rec*3 {
						thirtyDaysAgo := now.Add(-30 * 24 * time.Hour)
						var expiredDomains []string
						var activeDomains []DomainInfo

						for domain, info := range domainInfoMap {
							if info.LastUpdate.Before(thirtyDaysAgo) {
								expiredDomains = append(expiredDomains, domain)
							} else {
								activeDomains = append(activeDomains, *info)
							}
						}

						for _, domain := range expiredDomains {
							delete(domainInfoMap, domain)
						}

						if len(domainInfoMap) > max_rec*2 {
							sort.Slice(activeDomains, func(i, j int) bool {
								return activeDomains[i].Download+activeDomains[i].Upload > activeDomains[j].Download+activeDomains[j].Upload
							})

							keepSize := max_rec * 2
							if len(activeDomains) > keepSize {
								activeDomains = activeDomains[:keepSize]
							}

							domainInfoMap = make(map[string]*DomainInfo, len(activeDomains))
							for i := range activeDomains {
								domainInfoMap[activeDomains[i].Domain] = &activeDomains[i]
							}
						}
					}
					domainMutex.Unlock()
				}
			}
		}()

		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			domainMutex.RLock()
			domainInfoList := make(DomainInfoList, 0, len(domainInfoMap))
			for _, info := range domainInfoMap {
				cleanedIPs := make([]string, 0, len(info.ClientIPs))
				hasRealIP := false

				for _, ip := range info.ClientIPs {
					if ip != "127.0.0.1" {
						hasRealIP = true
						cleanedIPs = append(cleanedIPs, ip)
					}
				}

				if !hasRealIP && len(info.ClientIPs) > 0 {
					cleanedIPs = []string{"127.0.0.1"}
				}

				infoCopy := *info
				infoCopy.ClientIPs = cleanedIPs
				domainInfoList = append(domainInfoList, infoCopy)
			}
			domainMutex.RUnlock()

			sort.Sort(domainInfoList)
			if len(domainInfoList) > max_rec {
				domainInfoList = domainInfoList[:max_rec]
			}
			if len(domainInfoList) == 0 {
				placeholderTime, _ := time.Parse(time.RFC3339, "1970-01-01T00:00:00.2822102Z")
				domainInfoList = DomainInfoList{
					{
						Domain:     "clean-wait.paopao.gateway",
						Download:   0,
						Upload:     0,
						Total:      0,
						ClientIPs:  []string{"127.0.0.1"},
						LastUpdate: placeholderTime,
					},
				}
			}
			newFilePath := recPath + "/data.json.new"
			oldFilePath := recPath + "/data.json.old"
			currentFilePath := recPath + "/data.json"

			jsonData, err := json.MarshalIndent(domainInfoList, "", "  ")
			if err != nil {
				fmt.Printf("\n"+red+"[PaoPaoGW REC]"+reset+"Failed to marshal JSON: %v\n", err)
				continue
			}

			if err := os.WriteFile(newFilePath, jsonData, 0644); err != nil {
				continue
			}

			if _, err := os.Stat(currentFilePath); err == nil {
				os.Rename(currentFilePath, oldFilePath)
			}
			if err := os.Rename(newFilePath, currentFilePath); err != nil {
				fmt.Printf("\n"+red+"[PaoPaoGW REC]"+reset+"Failed to replace JSON file: %v\n", err)
				if _, err := os.Stat(oldFilePath); err == nil {
					os.Rename(oldFilePath, currentFilePath)
				}
			} else {
				if _, err := os.Stat(oldFilePath); err == nil {
					os.Remove(oldFilePath)
				}
			}
		}
		os.Exit(0)
	}
	//clash_yaml reload
	if reload {
		dropPrivileges()
		err := reloadYaml(apiURL, secret)
		if err != nil {
			fmt.Printf(red+"[PaoPaoGW Reload]"+reset+"ERR: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n" + green + "[PaoPaoGW Reload]" + reset + "Yaml reload OK. \n")
		os.Exit(0)
	}
	//test_http_code
	if testProxy != "" {
		dropPrivileges()
		if testNodeURL == "" || testProxy == "" {
			fmt.Println("Please provide URL and HTTP proxy parameters")
			flag.Usage()
			os.Exit(1)
		}
		_, code, err := checkURLConnectivity(testNodeURL, testProxy, "0")

		if err != nil {
			fmt.Println("Request error:", err)
			os.Exit(1)
		}

		fmt.Println("Node Check success. HTTP CODE:", code)
		os.Exit(0)
	}

	//clashapi ./ppgw -apiurl="http://10.10.10.3:9090" -secret="clashpass" -test_node_url="https://www.google.com" -ext_node="ong|Traffic|Expire| GB"
	//closeall conn
	if closeall {
		dropPrivileges()
		if secret == "" || apiURL == "" {
			os.Exit(1)
		}
		err := deleteConnections(apiURL, secret)
		if err != nil {
			fmt.Printf(red+"[PaoPaoGW Close]"+reset+"Unable to close connections: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if now_node {
		dropPrivileges()
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
		dropPrivileges()
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
		dropPrivileges()
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
	if ppsubFile != "" {
		if os.Getenv("dns_burn") == "yes" {
			dnsBurn = true
		}
		if exDNSEnv := os.Getenv("ex_dns"); exDNSEnv != "" {
			exDNS = exDNSEnv
		}
		err := processPPSub(ppsubFile, outputFile, dnsBurn, exDNS)
		if err != nil {
			fmt.Printf(red+"[PaoPaoGW PPSub]"+reset+"PPSub processing failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+"PPSub processed successfully, output file: %s\n", outputFile)
		os.Exit(0)
	}
	//gen_host
	if rawURL != "" {
		dropPrivileges()
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
	if input_cleanday != "" {
		result := checkCleanDay(input_cleanday)
		fmt.Print(result)
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
	// dns_burn
	if dnslist != "" {
		if inputFile == "" {
			fmt.Println("Please provide an input YAML file using the -dnsinput flag")
			os.Exit(1)
		}

		data, err := os.ReadFile(inputFile)
		if err != nil {
			fmt.Println("Error reading input file:", err)
			os.Exit(1)
		}

		var config map[string]interface{}
		if err := yaml.Unmarshal(data, &config); err != nil {
			fmt.Println("Error unmarshalling YAML: ", err)
			os.Exit(1)
		}

		proxies, ok := config["proxies"].([]interface{})
		if !ok {
			fmt.Println("No 'proxies' found in the YAML file")
			os.Exit(1)
		}

		dnsServers := strings.Split(dnslist, ",")

		for i, dns := range dnsServers {
			dns = strings.TrimSpace(dns)
			if !strings.Contains(dns, ":") {
				dnsServers[i] = dns + ":53"
			} else {
				dnsServers[i] = dns
			}
		}
		usedNames := make(map[string]bool)
		for _, proxy := range proxies {
			if p, ok := proxy.(map[interface{}]interface{}); ok {
				if name, ok := p["name"].(string); ok {
					usedNames[name] = true
				}
			}
		}
		var newProxies []interface{}
		var wg sync.WaitGroup
		var mu sync.Mutex

		fmt.Printf(green+"[PaoPaoGW DNS]"+reset+"DNS List: %v\n", dnsServers)
		fmt.Printf(green + "[PaoPaoGW DNS]" + reset + "Start DNS Burn process...\n")

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

			name := ""
			if n, ok := p["name"].(string); ok {
				name = n
			}

			wg.Add(1)
			go func(name, server string, originalProxy map[interface{}]interface{}) {
				defer wg.Done()

				if net.ParseIP(server) != nil {
					// fmt.Printf(orange+"[PaoPaoGW DNS]"+reset+"%s (%s) is already an IP address, skipping\n", name, server)
					return
				}

				serverList := resolveDomainIPs(server, dnsServers)

				if len(serverList) == 0 {
					fmt.Printf(orange+"[PaoPaoGW DNS]"+reset+"%s (%s) DNS resolution returned no results\n", name, server)
					return
				}

				fmt.Printf(green+"[PaoPaoGW DNS]"+reset+"DNS Burn: %s -> %v\n", server, serverList)

				mu.Lock()
				defer mu.Unlock()

				for _, serverAddr := range serverList {
					uniqueName := generateNodeName(name, serverAddr, usedNames)
					usedNames[uniqueName] = true

					newProxy := make(map[interface{}]interface{})
					for key, value := range originalProxy {
						newProxy[key] = value
					}
					newProxy["name"] = uniqueName
					newProxy["server"] = serverAddr
					newProxies = append(newProxies, newProxy)
					fmt.Printf(green+"[PaoPaoGW DNS]"+reset+"  + Add Node: %s\n", uniqueName)
				}
			}(name, server, p)
		}

		wg.Wait()
		config["proxies"] = append(proxies, newProxies...)

		newData, err := yaml.Marshal(&config)
		if err != nil {
			fmt.Println("Error marshalling new YAML:", err)
			os.Exit(1)
		}

		if err := os.WriteFile(outputFile, newData, 0644); err != nil {
			fmt.Println("Error writing output file: ", err)
			os.Exit(1)
		}

		fmt.Printf(green+"[PaoPaoGW DNS]"+reset+"New configuration written to %s (Added %d nodes)\n", outputFile, len(newProxies))
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
	return d[i].Total > d[j].Total
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

func QueryDNSIPs(ctx context.Context, domain *string, dnsServer string) ([]net.IP, error) {
	dnsResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: 1 * time.Second,
			}
			if !strings.Contains(dnsServer, ":") {
				return dialer.DialContext(ctx, "udp", dnsServer+":53")
			}
			return dialer.DialContext(ctx, "udp", dnsServer)
		},
	}

	networkType := "ip4"
	if ipv6Enabled {
		networkType = "ip"
	}

	ips, err := dnsResolver.LookupIP(ctx, networkType, *domain)
	if err != nil {
		return nil, fmt.Errorf("lookup failed via %s: %w", dnsServer, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no records found for domain: %s", *domain)
	}

	return ips, nil
}

func NewDownloader(url, outputFile string) *Downloader {
	userAgent := "ClashforWindows/clash-verge/Clash/clash"
	if _, err := os.Stat("/www/clash_core"); err == nil {
		userAgent = "clash-verge/v1.6.6" //auto update, do not change
	}
	return &Downloader{
		URL:        url,
		OutputFile: outputFile,
		UserAgent:  userAgent,
		Timeout:    10 * time.Second,
	}
}

func (d *Downloader) Download() error {
	var dnsServers []string

	dnsIP := os.Getenv("dns_ip")
	dnsPort := os.Getenv("dns_port")
	if dnsIP != "" {
		if dnsPort != "" {
			dnsServers = append(dnsServers, net.JoinHostPort(dnsIP, dnsPort))
		} else {
			dnsServers = append(dnsServers, dnsIP+":53")
		}
	}

	exDNS := os.Getenv("ex_dns")
	if exDNS != "" {
		servers := strings.Split(exDNS, ",")
		for _, s := range servers {
			s = strings.TrimSpace(s)
			if s != "" {
				if !strings.Contains(s, ":") {
					s = s + ":53"
				}
				dnsServers = append(dnsServers, s)
			}
		}
	}
	fmt.Printf(green+"[PaoPaoGW Get]"+reset+"DNS List: %s\n", dnsServers)
	for _, dnsServer := range dnsServers {
		fmt.Printf(green+"[PaoPaoGW Get]"+reset+"Trying Custom DNS: %s\n", dnsServer)
		err := d.downloadWithCustomDNS(dnsServer)
		if err == nil {
			return nil
		}
		fmt.Printf(orange+"[PaoPaoGW Get]"+reset+"Custom DNS %s failed: %v\n", dnsServer, err)
	}

	fmt.Printf(green + "[PaoPaoGW Get]" + reset + "Trying System DNS...\n")
	err := d.downloadWithSystemDNS()
	if err == nil {
		return nil
	}
	fmt.Printf(orange+"[PaoPaoGW Get]"+reset+"System DNS failed: %v\n", err)

	fmt.Printf(green + "[PaoPaoGW Get]" + reset + "Trying Socks5 Proxy...\n")
	err = d.downloadWithSocks5("127.0.0.1:1080")
	if err == nil {
		return nil
	}
	fmt.Printf(red + "[PaoPaoGW Get]" + reset + "Download failed.\n")

	return fmt.Errorf("All download methods failed")
}

func (d *Downloader) GetHeader(key string) string {
	if d.Headers == nil {
		return ""
	}
	return d.Headers.Get(key)
}

func (d *Downloader) GetAllHeaders() http.Header {
	return d.Headers
}

func (d *Downloader) downloadWithSystemDNS() error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: d.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			req.Header.Set("User-Agent", d.UserAgent)
			return nil
		},
	}

	return d.doDownload(client)
}

func (d *Downloader) downloadWithCustomDNS(dnsServer string) error {
	dialer := &net.Dialer{
		Timeout:   d.Timeout,
		KeepAlive: 30 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dnsDialer := net.Dialer{Timeout: 1 * time.Second}
				return dnsDialer.DialContext(ctx, "udp", dnsServer)
			},
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DialContext:       dialer.DialContext,
			ForceAttemptHTTP2: false,
		},
		Timeout: d.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			req.Header.Set("User-Agent", d.UserAgent)
			return nil
		},
	}

	return d.doDownload(client)
}

func (d *Downloader) downloadWithSocks5(proxyAddr string) error {
	proxyURL, err := url.Parse("socks5://" + proxyAddr)
	if err != nil {
		return fmt.Errorf("invalid proxy address: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: d.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			req.Header.Set("User-Agent", d.UserAgent)
			return nil
		},
	}

	return d.doDownload(client)
}

func (d *Downloader) doDownload(client *http.Client) error {
	req, err := http.NewRequest("GET", d.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", d.UserAgent)

	var remoteAddr string
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			if connInfo.Conn != nil {
				remoteAddr = connInfo.Conn.RemoteAddr().String()
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	parsedURL, _ := url.Parse(d.URL)
	host := parsedURL.Hostname()
	if parsedURL.Scheme == "http" && net.ParseIP(host) != nil {
		req.Host = "paopao.dns"
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	d.Headers = resp.Header.Clone()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("request failed with status code %d", resp.StatusCode)
	}

	finalURL := resp.Request.URL.String()
	finalHost := resp.Request.URL.Hostname()

	if remoteAddr != "" {
		fmt.Printf(orange+"[PaoPaoGW Get]"+reset+"HOST: %s IP: %s\n", finalHost, remoteAddr)
	} else {
		addrs, err := net.LookupHost(finalHost)
		if err == nil && len(addrs) > 0 {
			fmt.Printf(orange+"[PaoPaoGW Get]"+reset+"HOST: %s IP: %s\n", finalHost, strings.Join(addrs, ", "))
		} else {
			fmt.Printf(orange+"[PaoPaoGW Get]"+reset+"HOST: %s\n", finalHost)
		}
	}

	if finalURL != d.URL {
		fmt.Printf(orange+"[PaoPaoGW Get]"+reset+"Redirected URL: %s\n", finalURL)
	}

	file, err := os.Create(d.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}

	return nil
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

	var v6Candidate string

	for _, ipAddr := range r {
		ip := ipAddr.IP
		if ip.To4() != nil {
			return ip.String()
		}
		if ipv6Enabled && ip.To4() == nil && ip.To16() != nil {
			if v6Candidate == "" {
				v6Candidate = ip.String()
			}
		}
	}

	if v6Candidate != "" {
		return v6Candidate
	}

	os.Exit(1)
	return ""
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
	systemNodes := []string{"REJECT", "DIRECT", "GLOBAL", "UNKNOWN", "COMPATIBLE", "PASS", "REJECT-DROP"}
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
func isValidDestination(destination string) bool {
	if destination == "" {
		return false
	}

	ip := net.ParseIP(destination)
	if ip == nil {
		return true
	}

	if ip[0] == 0 {
		return false
	}
	return true
}
func checkCleanDay(inputDay string) string {
	day, err := strconv.Atoi(inputDay)
	if err != nil {
		return "0"
	}

	if day < 1 || day > 31 {
		return "0"
	}

	now := time.Now()
	year, month, _ := now.Date()
	currentDay := now.Day()

	firstDayNextMonth := time.Date(year, month+1, 1, 0, 0, 0, 0, now.Location())
	lastDayThisMonth := firstDayNextMonth.Add(-24 * time.Hour).Day()

	targetDay := day
	if day > lastDayThisMonth {
		targetDay = lastDayThisMonth
	}

	if currentDay != targetDay {
		return "0"
	}

	recordFile := "/tmp/ppgw_netrec_cleanday"
	currentDateStr := fmt.Sprintf("%04d%02d%02d", year, month, currentDay)

	lastExecDate, err := os.ReadFile(recordFile)
	if err == nil {
		if string(lastExecDate) == currentDateStr {
			return "0"
		}
	}

	err = os.WriteFile(recordFile, []byte(currentDateStr), 0644)
	if err != nil {
		return "0"
	}

	return "1"
}
func processPPSub(configFile, outputFile string, dnsBurn bool, exDNS string) error {
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("Failed to read config file: %v", err)
	}

	var config PPSubConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("Failed to parse config file: %v", err)
	}

	fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"Config info: %d subscriptions, %d node groups, %d rule sets\n",
		len(config.Subs), len(config.NodeGroups), len(config.Rules))

	if dnsBurn {
		fmt.Printf(green + "[PaoPaoGW PPSub]" + reset + "DNS Burn mode: enabled\n")
		if exDNS != "" {
			fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+"Extra DNS: %s\n", exDNS)
		}
	} else {
		fmt.Printf(orange + "[PaoPaoGW PPSub]" + reset + "DNS Burn mode: disabled\n")
	}

	fmt.Printf("\n" + orange + "[PaoPaoGW PPSub]" + reset + "========== Step 1/4: Download subscriptions ==========\n")
	subResults := make(map[string]*SubDownloadResult)
	hasSuccess := false
	successCount := 0

	for _, sub := range config.Subs {
		result := downloadSubscription(sub)
		subResults[sub.Name] = result

		if result.Success {
			hasSuccess = true
			successCount++
			forcedTag := ""
			if sub.IsForced {
				forcedTag = " [forced]"
			}
			fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+" %s%s downloaded successfully (%d nodes)\n", sub.Name, forcedTag, len(result.Proxies))
		} else {
			if sub.IsForced {
				return fmt.Errorf("Required subscription %s failed to download: %v", sub.Name, result.Error)
			}
			fmt.Printf(red+"[PaoPaoGW PPSub]"+reset+" %s download failed: %v\n", sub.Name, result.Error)
		}
	}

	if !hasSuccess {
		return fmt.Errorf("All subscription providers failed to download")
	}

	fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+"Subscription download complete: %d/%d successful\n", successCount, len(config.Subs))

	fmt.Printf("\n" + orange + "[PaoPaoGW PPSub]" + reset + "========== Step 2/4: Processing proxy nodes ==========\n")
	allProxies, err := processProxies(subResults, dnsBurn, exDNS)
	if err != nil {
		return fmt.Errorf("Failed to process proxy nodes: %v", err)
	}
	fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+" Get %d proxy nodes\n", len(allProxies))

	fmt.Printf("\n" + orange + "[PaoPaoGW PPSub]" + reset + "========== Step 3/4: Generating proxy groups ==========\n")
	proxyGroups, proxyProviders, err := generateProxyGroups(config.NodeGroups, allProxies, subResults)
	if err != nil {
		return fmt.Errorf("Failed to generate proxy groups: %v", err)
	}
	fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+" Generated %d proxy groups, %d proxy providers\n", len(proxyGroups), len(proxyProviders))

	fmt.Printf("\n" + orange + "[PaoPaoGW PPSub]" + reset + "========== Step 4/4: Processing rules ==========\n")
	rules, ruleProviders, err := processRules(config.Rules, proxyGroups)
	if err != nil {
		return fmt.Errorf("Failed to process rules: %v", err)
	}
	fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+" Generated %d rules, %d rule providers\n", len(rules), len(ruleProviders))

	finalConfig := ClashConfig{
		Proxies:        allProxies,
		ProxyGroups:    proxyGroups,
		ProxyProviders: proxyProviders,
		Rules:          rules,
		RuleProviders:  ruleProviders,
		Mode:           "rule",
	}

	yamlData, err := yaml.Marshal(&finalConfig)
	if err != nil {
		return fmt.Errorf("Failed to generate YAML: %v", err)
	}

	if err := os.WriteFile(outputFile, yamlData, 0644); err != nil {
		return fmt.Errorf("Failed to write output file: %v", err)
	}

	fmt.Printf("\n" + green + "[PaoPaoGW PPSub]" + reset + "========== Processing complete ==========\n")

	return nil
}

type SubDownloadResult struct {
	Success     bool
	Proxies     []map[string]interface{}
	UserInfo    *SubscriptionUserInfo
	Error       error
	RawResponse *http.Response
}

func downloadSubscription(sub SubProvider) *SubDownloadResult {
	result := &SubDownloadResult{Success: false}

	var lastErr error
	for retry := 0; retry < 3; retry++ {
		if retry > 0 {
			fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"Retrying download %s (attempt %d)...\n", sub.Name, retry+1)
			time.Sleep(time.Second * time.Duration(retry))
		}

		tmpFile := fmt.Sprintf("/tmp/ppsub_%s_%d.yaml", sub.Name, time.Now().Unix())
		defer os.Remove(tmpFile)

		downloader := NewDownloader(sub.URL, tmpFile)
		err := downloader.Download()
		if err != nil {
			lastErr = err
			continue
		}

		headers := downloader.Headers

		if userInfoHeader := headers.Get("subscription-userinfo"); userInfoHeader != "" {
			userInfo := parseSubscriptionUserInfo(userInfoHeader)
			if userInfo != nil {
				result.UserInfo = userInfo
				fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+" %s  \n", sub.Name)
			}
		}

		data, err := os.ReadFile(tmpFile)
		if err != nil {
			lastErr = err
			continue
		}

		var yamlData map[string]interface{}
		if err := yaml.Unmarshal(data, &yamlData); err != nil {
			lastErr = err
			continue
		}

		if proxies, ok := yamlData["proxies"].([]interface{}); ok {
			for _, p := range proxies {
				if proxyMap, ok := p.(map[interface{}]interface{}); ok {
					convertedProxy := make(map[string]interface{})
					for k, v := range proxyMap {
						if keyStr, ok := k.(string); ok {
							convertedProxy[keyStr] = v
						}
					}

					if name, ok := convertedProxy["name"].(string); ok {
						convertedProxy["name"] = fmt.Sprintf("%s_%s", sub.Name, name)
					}

					result.Proxies = append(result.Proxies, convertedProxy)
				}
			}
		}

		result.Success = true
		return result
	}

	result.Error = lastErr
	return result
}

func parseSubscriptionUserInfo(header string) *SubscriptionUserInfo {
	userInfo := &SubscriptionUserInfo{}
	parts := strings.Split(header, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		intValue, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}

		switch key {
		case "upload":
			userInfo.Upload = intValue
		case "download":
			userInfo.Download = intValue
		case "total":
			userInfo.Total = intValue
		case "expire":
			userInfo.Expire = intValue
		}
	}

	if userInfo.Total > 0 && userInfo.Expire > 0 {
		return userInfo
	}

	return nil
}
func processProxies(subResults map[string]*SubDownloadResult, dnsBurn bool, exDNS string) ([]map[string]interface{}, error) {
	var allProxies []map[string]interface{}
	var userInfo *SubscriptionUserInfo
	var userInfoSubName string

	usedNames := make(map[string]bool)

	var dnsServers []string
	envDNSIP := os.Getenv("dns_ip")
	envDNSPort := os.Getenv("dns_port")

	if envDNSIP != "" {
		if envDNSPort != "" {
			dnsServers = append(dnsServers, net.JoinHostPort(envDNSIP, envDNSPort))
		} else {
			dnsServers = append(dnsServers, envDNSIP)
		}
		fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+"Using env DNS: %s\n", dnsServers[0])
	}

	if exDNS != "" {
		exList := strings.Split(exDNS, ",")
		dnsServers = append(dnsServers, exList...)
	}

	if len(dnsServers) > 0 {
		fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+"Combined DNS List: %v\n", dnsServers)
	}

	for subName, result := range subResults {
		if !result.Success {
			continue
		}

		if userInfo == nil && result.UserInfo != nil {
			userInfo = result.UserInfo
			userInfoSubName = subName
			fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+"USE %s traffic info\n", subName)
		}

		for _, proxy := range result.Proxies {
			if name, ok := proxy["name"].(string); ok {
				usedNames[name] = true
			}
			allProxies = append(allProxies, proxy)

			if dnsBurn {
				if server, ok := proxy["server"].(string); ok {
					if net.ParseIP(server) == nil {
						ips := resolveDomainIPs(server, dnsServers)
						if len(ips) > 0 {
							fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"DNS Burn: %s -> %v\n", server, ips)

							originalName := ""
							if name, ok := proxy["name"].(string); ok {
								originalName = name
							}

							for _, ip := range ips {
								ipProxy := make(map[string]interface{})
								for k, v := range proxy {
									ipProxy[k] = v
								}
								ipProxy["server"] = ip

								newName := generateNodeName(originalName, ip, usedNames)
								ipProxy["name"] = newName

								usedNames[newName] = true

								allProxies = append(allProxies, ipProxy)
							}
						}
					} else {
						fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"DNS Burn: %s is already an IP address, skipping\n", server)
					}
				}
			}
		}
	}

	if userInfo != nil && len(allProxies) >= 1 {
		remaining := float64(userInfo.Total-userInfo.Upload-userInfo.Download) / 1073741824
		total := float64(userInfo.Total) / 1073741824
		expireDate := time.Unix(userInfo.Expire, 0).Format("2006-01-02")

		fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+"Added traffic info virtual node: remaining %.2fG/%.2fG, expiry %s\n", remaining, total, expireDate)

		templateProxy := allProxies[len(allProxies)-1]

		expireNode := make(map[string]interface{})
		for k, v := range templateProxy {
			expireNode[k] = v
		}
		expireNode["name"] = fmt.Sprintf("%s_至To %s", userInfoSubName, expireDate)

		trafficNode := make(map[string]interface{})
		for k, v := range templateProxy {
			trafficNode[k] = v
		}
		trafficNode["name"] = fmt.Sprintf("%s_余Left %.2fG/%.2fG", userInfoSubName, remaining, total)

		allProxies = append([]map[string]interface{}{expireNode, trafficNode}, allProxies...)
	}

	return allProxies, nil
}

func resolveDomainIPs(domain string, extraDNS []string) []string {
	ipSet := make(map[string]bool)
	for _, dnsServer := range extraDNS {
		dnsServer = strings.TrimSpace(dnsServer)
		if dnsServer == "" {
			continue
		}

		if !strings.Contains(dnsServer, ":") {
			dnsServer = dnsServer + ":53"
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		ips, err := QueryDNSIPs(ctx, &domain, dnsServer)
		cancel()
		if err == nil {
			for _, ip := range ips {
				if ip.To4() != nil {
					ipSet[ip.String()] = true
				} else if ipv6Enabled && ip.To16() != nil {
					ipSet[ip.String()] = true
				}
			}
		} else {
			fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"DNS query failed (via %s): %v\n", dnsServer, err)
		}
	}

	var result []string
	for ip := range ipSet {
		result = append(result, ip)
	}
	sort.Strings(result)

	return result
}
func generateProxyGroups(nodeGroups []NodeGroup, allProxies []map[string]interface{}, subResults map[string]*SubDownloadResult) ([]map[string]interface{}, map[string]interface{}, error) {
	var proxyGroups []map[string]interface{}
	proxyProviders := make(map[string]interface{})

	groupDirectProxies := make(map[string][]string)
	groupMap := make(map[string]NodeGroup)
	potentialGroups := make([]string, 0, len(nodeGroups))

	groupFullProxies := make(map[string][]map[string]interface{})

	for _, group := range nodeGroups {
		groupMap[group.Name] = group
		if !checkSubDependencies(group.Subs, subResults) {
			fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"Skipping node group %s (dependent subscription not downloaded)\n", group.Name)
			continue
		}

		matchedProxies := filterProxiesByGroup(group, allProxies, subResults)
		groupDirectProxies[group.Name] = matchedProxies
		potentialGroups = append(potentialGroups, group.Name)

		if group.UsePreProxy {
			fullProxies := filterProxiesObjectsByGroup(group, allProxies)
			groupFullProxies[group.Name] = fullProxies
		}
	}

	isValid := make(map[string]bool)

	for _, name := range potentialGroups {
		if len(groupDirectProxies[name]) > 0 {
			isValid[name] = true
		}
	}

	changed := true
	for changed {
		changed = false
		for _, name := range potentialGroups {
			if isValid[name] {
				continue
			}
			group := groupMap[name]
			for _, includedName := range group.Include {
				if _, exists := groupMap[includedName]; exists && isValid[includedName] {
					isValid[name] = true
					changed = true
					break
				}
			}
		}
	}

	for _, group := range nodeGroups {
		if _, ok := groupDirectProxies[group.Name]; !ok {
			continue
		}

		if !isValid[group.Name] {
			fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"Skipping node group %s (no matching nodes and no valid included groups)\n", group.Name)
			continue
		}

		proxyGroup := make(map[string]interface{})
		proxyGroup["name"] = group.Name

		// Handle Pre-Proxy Logic
		if group.UsePreProxy && group.PreProxyGroup != "" {
			providerName := fmt.Sprintf("%s=(%s🔗%s)", group.Name, group.PreProxyGroup, group.Name)

			// Generate Proxy Provider
			provider := map[string]interface{}{
				"type": "inline",
				"override": map[string]interface{}{
					"dialer-proxy": group.PreProxyGroup,
				},
				"payload": groupFullProxies[group.Name],
			}
			proxyProviders[providerName] = provider

			proxyGroup["use"] = []string{providerName}
		} else {
			finalProxies := make([]string, 0, len(groupDirectProxies[group.Name])+len(group.Include))
			finalProxies = append(finalProxies, groupDirectProxies[group.Name]...)

			for _, incName := range group.Include {
				if isValid[incName] {
					finalProxies = append(finalProxies, incName)
				}
			}
			proxyGroup["proxies"] = finalProxies
		}

		if group.SpeedtestURL != "" && strings.TrimSpace(group.SpeedtestURL) != "" {
			proxyGroup["type"] = "url-test"
			proxyGroup["url"] = group.SpeedtestURL

			interval := group.Interval
			if interval == 0 {
				interval = 600
			}
			if interval < 30 {
				interval = 30
			}
			proxyGroup["interval"] = interval
			proxyGroup["tolerance"] = 0

			fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+"Node group %s: url-test mode (URL: %s, Interval: %d)\n",
				group.Name, group.SpeedtestURL, interval)
		} else {
			proxyGroup["type"] = "select"
			fmt.Printf(green+"[PaoPaoGW PPSub]"+reset+"Node group %s: select mode\n", group.Name)
		}

		proxyGroups = append(proxyGroups, proxyGroup)
	}

	return proxyGroups, proxyProviders, nil
}

func filterProxiesObjectsByGroup(group NodeGroup, allProxies []map[string]interface{}) []map[string]interface{} {
	var matched []map[string]interface{}

	incSimple, incRegex := parseKeywords(group.Keywords)
	excSimple, excRegex := parseKeywords(group.ExcludeKeywords)

	for _, proxy := range allProxies {
		name, ok := proxy["name"].(string)
		if !ok {
			continue
		}
		if isSystemNode(name) {
			continue
		}
		if !matchSubSource(name, group.Subs) {
			continue
		}

		if matchesAnyKeyword(name, excSimple, excRegex) {
			continue
		}

		if len(group.Keywords) > 0 && !matchesAnyKeyword(name, incSimple, incRegex) {
			continue
		}

		matched = append(matched, proxy)
	}

	return matched
}

func checkSubDependencies(subs []string, subResults map[string]*SubDownloadResult) bool {
	if len(subs) == 0 || (len(subs) == 1 && subs[0] == "all") {
		return true
	}

	for _, subName := range subs {
		if subName == "all" {
			continue
		}
		if result, ok := subResults[subName]; !ok || !result.Success {
			return false
		}
	}
	return true
}
func parseKeywords(keywords []string) ([]string, []*regexp.Regexp) {
	var simple []string
	var regexes []*regexp.Regexp

	for _, k := range keywords {
		if strings.HasPrefix(k, "exp#") {
			pattern := strings.TrimPrefix(k, "exp#")
			re, err := regexp.Compile(pattern)
			if err != nil {
				fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"Regex compile error for '%s': %v (Skipping)\n", k, err)
				continue
			}
			regexes = append(regexes, re)
		} else {
			simple = append(simple, k)
		}
	}
	return simple, regexes
}
func filterProxiesByGroup(group NodeGroup, allProxies []map[string]interface{}, subResults map[string]*SubDownloadResult) []string {
	var matched []string

	incSimple, incRegex := parseKeywords(group.Keywords)
	excSimple, excRegex := parseKeywords(group.ExcludeKeywords)

	for _, proxy := range allProxies {
		name, ok := proxy["name"].(string)
		if !ok {
			continue
		}
		if isSystemNode(name) {
			continue
		}
		if !matchSubSource(name, group.Subs) {
			continue
		}

		if matchesAnyKeyword(name, excSimple, excRegex) {
			continue
		}

		if len(group.Keywords) > 0 && !matchesAnyKeyword(name, incSimple, incRegex) {
			continue
		}

		matched = append(matched, name)
	}

	return matched
}

func matchSubSource(proxyName string, subs []string) bool {
	if subs == nil {
		return true
	}

	if len(subs) == 0 {
		return false
	}

	for _, sub := range subs {
		if sub == "all" {
			return true
		}
		if strings.HasPrefix(proxyName, sub+"_") {
			return true
		}
	}
	return false
}

func matchesAnyKeyword(text string, simple []string, regexes []*regexp.Regexp) bool {
	for _, keyword := range simple {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	for _, re := range regexes {
		if re.MatchString(text) {
			return true
		}
	}

	return false
}

func processRules(ruleSets []RuleSet, proxyGroups []map[string]interface{}) ([]string, map[string]interface{}, error) {
	sort.Slice(ruleSets, func(i, j int) bool {
		return ruleSets[i].Priority < ruleSets[j].Priority
	})

	groupNames := make(map[string]bool)
	for _, group := range proxyGroups {
		if name, ok := group["name"].(string); ok {
			groupNames[name] = true
		}
	}

	var allRules []string
	definedProviders := make(map[string]map[string]interface{})

	for _, ruleSet := range ruleSets {
		if ruleSet.Type == "rule-set" {
			if ruleSet.Name == "" || ruleSet.URL == "" {
				continue
			}
			provider := map[string]interface{}{
				"type":     "http",
				"url":      ruleSet.URL,
				"interval": 86400,
				"behavior": "classical",
				"header": map[string]interface{}{
					"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0 gzip, deflate, br"},
				},
			}
			if ruleSet.Behavior != "" {
				provider["behavior"] = ruleSet.Behavior
			}
			if ruleSet.Interval > 0 {
				provider["interval"] = ruleSet.Interval
			}
			if ruleSet.Interval < 60 {
				provider["interval"] = 60
			}
			if ruleSet.Format != "" {
				provider["format"] = ruleSet.Format
			}
			if ruleSet.Proxy != "" {
				provider["proxy"] = ruleSet.Proxy
			}

			definedProviders[ruleSet.Name] = provider
			continue
		}

		var rules []string

		if ruleSet.Type == "url" || (ruleSet.Type == "" && ruleSet.URL != "") {
			downloadedRules, err := downloadRules(ruleSet.URL)
			if err != nil {
				if ruleSet.IsForced {
					return nil, nil, fmt.Errorf("Required rule download failed (URL: %s): %v", ruleSet.URL, err)
				}
				fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"Failed to download rule (URL: %s): %v\n", ruleSet.URL, err)
				continue
			}
			rules = downloadedRules
		} else {
			rules = ruleSet.FixRule
		}

		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}

			if !validateRule(rule, groupNames) {
				fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"Skipping rule (referenced proxy group does not exist): %s\n", rule)
				continue
			}

			allRules = append(allRules, rule)
		}
	}

	finalProviders := make(map[string]interface{})
	usedProviderNames := make(map[string]bool)

	for _, rule := range allRules {
		if strings.HasPrefix(strings.ToUpper(rule), "RULE-SET") {
			parts := strings.Split(rule, ",")
			if len(parts) >= 2 {
				providerName := strings.TrimSpace(parts[1])
				usedProviderNames[providerName] = true
			}
		}
	}

	for name, provider := range definedProviders {
		if usedProviderNames[name] {
			finalProviders[name] = provider
		} else {
			fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"Pruning unused rule provider: %s\n", name)
		}
	}

	return allRules, finalProviders, nil
}

func downloadRules(ruleURL string) ([]string, error) {
	var lastErr error
	for retry := 0; retry < 3; retry++ {
		if retry > 0 {
			fmt.Printf(orange+"[PaoPaoGW PPSub]"+reset+"Retrying rule download (attempt %d)...\n", retry+1)
			time.Sleep(time.Second * time.Duration(retry))
		}

		tmpFile := fmt.Sprintf("/tmp/ppsub_rules_%d.yaml", time.Now().Unix())
		defer os.Remove(tmpFile)

		downloader := NewDownloader(ruleURL, tmpFile)
		err := downloader.Download()
		if err != nil {
			lastErr = err
			continue
		}

		data, err := os.ReadFile(tmpFile)
		if err != nil {
			lastErr = err
			continue
		}

		var yamlData map[string]interface{}
		if err := yaml.Unmarshal(data, &yamlData); err != nil {
			lastErr = err
			continue
		}

		if rules, ok := yamlData["rules"].([]interface{}); ok {
			var result []string
			for _, r := range rules {
				if ruleStr, ok := r.(string); ok {
					result = append(result, ruleStr)
				}
			}
			return result, nil
		}

		return nil, fmt.Errorf("rules Not found in downloaded data.")
	}

	return nil, lastErr
}

func validateRule(rule string, groupNames map[string]bool) bool {
	parts := strings.Split(rule, ",")
	if len(parts) < 2 {
		return true
	}

	ruleOptions := map[string]bool{
		"no-resolve": true,
		"src":        true,
		"dst":        true,
		"no-redir":   true,
		"not":        true,
	}

	targetIndex := len(parts) - 1
	for targetIndex >= 0 {
		candidate := strings.TrimSpace(parts[targetIndex])
		candidateLower := strings.ToLower(candidate)
		if !ruleOptions[candidateLower] {
			break
		}
		targetIndex--
	}

	if targetIndex < 1 {
		return true
	}

	target := strings.TrimSpace(parts[targetIndex])

	builtinPolicies := map[string]bool{
		"DIRECT":  true,
		"REJECT":  true,
		"PROXY":   true,
		"proxies": true,
	}

	if builtinPolicies[target] {
		return true
	}

	return groupNames[target]
}
func checkURLConnectivity(targetURL, proxyAddr, expectedStatus string) (bool, int, error) {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return false, 0, fmt.Errorf("invalid proxy address: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false, 0, fmt.Errorf("invalid URL: %v", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return false, 0, err
	}
	resp.Body.Close()

	statusCode := resp.StatusCode
	success := false

	if expectedStatus == "0" || expectedStatus == "" {
		success = true
	} else if strings.Contains(expectedStatus, "-") {
		parts := strings.Split(expectedStatus, "-")
		if len(parts) == 2 {
			min, _ := strconv.Atoi(parts[0])
			max, _ := strconv.Atoi(parts[1])
			if statusCode >= min && statusCode <= max {
				success = true
			}
		}
	} else {
		expCode, _ := strconv.Atoi(expectedStatus)
		if statusCode == expCode {
			success = true
		}
	}

	return success, statusCode, nil
}

func generateSuffix(n int) string {
	s := ""
	for {
		remainder := n % 26
		s = string(rune('A'+remainder)) + s
		n = n/26 - 1
		if n < 0 {
			break
		}
	}
	return s
}

func generateNodeName(baseName, ip string, usedNames map[string]bool) string {
	if strings.Contains(ip, ":") {
		cleanIP := strings.ReplaceAll(ip, ":", "")
		suffix := ""
		if len(cleanIP) > 4 {
			suffix = cleanIP[len(cleanIP)-4:]
		} else {
			suffix = cleanIP
		}

		candidate := fmt.Sprintf("%s@%s", baseName, suffix)

		if !usedNames[candidate] {
			return candidate
		}
		counter := 0
		for {
			s := generateSuffix(counter)
			newCandidate := candidate + s
			if !usedNames[newCandidate] {
				return newCandidate
			}
			counter++
		}
	}
	parts := strings.Split(ip, ".")
	lastOctet := parts[len(parts)-1]

	candidate := fmt.Sprintf("%s@%s", baseName, lastOctet)

	if !usedNames[candidate] {
		return candidate
	}

	counter := 0
	for {
		suffix := generateSuffix(counter)
		newCandidate := candidate + suffix
		if !usedNames[newCandidate] {
			return newCandidate
		}
		counter++
	}
}
func checkIPv6Support() bool {
	content, err := os.ReadFile("/etc/config/network")
	if err != nil {
		return false
	}
	return strings.Contains(string(content), "eth06")
}
