package main

import (
	"archive/zip"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	red    = "\033[31m"
	green  = "\033[32m"
	cyan   = "\033[36m"
	yellow = "\033[33m"
	reset  = "\033[0m"
)

var asnDataDir string

const banner = `
       d8888                                     
      d88888                                     
     d88P888                                     
    d88P 888 .d8888b  88888b.   .d88b.   .d88b.  
   d88P  888 88K      888 "88b d88P"88b d88""88b 
  d88P   888 "Y8888b. 888  888 888  888 888  888 
 d8888888888      X88 888  888 Y88b 888 Y88..88P 
d88P     888  88888P' 888  888  "Y88888  "Y88P"  
                                    888          
                               Y8b d88P          
                                "Y88P"

                                 Made by VexilonHacker
`

type ASNJSON struct {
	ASN         int    `json:"asn"`
	Handle      string `json:"handle"`
	Description string `json:"description"`
	Subnets     struct {
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	} `json:"subnets"`
}

type ASNInfo struct {
	Query       string   `json:"query"`
	ASN         string   `json:"asn"`
	Description string   `json:"description"`
	Prefixes    []string `json:"prefixes,omitempty"`
	IP          string   `json:"ip,omitempty"`
}

func printBannerAndMsg() {

	fmt.Fprintf(os.Stderr, "%s%s%s\n", cyan, banner, reset)
	fmt.Fprintf(os.Stderr, "%s[+] Scan result follows below%s\n\n", green, reset)
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func ensureASNData() error {

	if _, err := os.Stat(asnDataDir); !os.IsNotExist(err) {
		return nil // already exists
	}
	if err := os.MkdirAll(asnDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %v", err)
	}
	fmt.Printf("%s[!] ASN database not found. Downloading for faster local lookups...%s\n", yellow, reset)

	zipURL := "https://github.com/ipverse/asn-ip/archive/refs/heads/master.zip"
	zipPath := "asn-master.zip"

	resp, err := http.Get(zipURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	size, _ := strconv.Atoi(resp.Header.Get("Content-Length"))
	unknownSize := false
	if size == 0 {
		fmt.Println("\033[33mWarning: Content-Length unknown, progress will show bytes instead of percent.\033[0m")
		unknownSize = true
	}

	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer out.Close()

	buf := make([]byte, 8*1024)
	var downloaded int
	barWidth := 50
	barEmpty := repeat(' ', barWidth)

	fmt.Printf("\033[34m[+] Starting download \033[0m[%s] \033[33m0.00%%\033[0m", barEmpty)

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			downloaded += n

			if !unknownSize {
				percent := float64(downloaded) / float64(size)
				if percent > 1 {
					percent = 1
				}
				filled := int(percent * float64(barWidth))
				bar := fmt.Sprintf("\033[42m%s\033[0m%s", repeat(' ', filled), repeat(' ', barWidth-filled))
				fmt.Printf("\r\033[34m[+] Starting download \033[0m[%s] \033[33m%.2f%%\033[0m", bar, percent*100)
			} else {
				fmt.Printf("\r\033[34m[+] Starting download \033[0m[%s] %d bytes", barEmpty, downloaded)
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}

	fmt.Printf("\r\033[34m[+] Starting download \033[0m[\033[42m%s\033[0m] \033[33m100.00%%\033[32m Download completed!\033[0m\n", repeat(' ', barWidth))

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	fmt.Printf("\033[34m[+] Extracting ASN DB \033[0m[%s] \033[33m0.00%%\033[0m", barEmpty)

	for i, f := range r.File {
		path := filepath.Join(".", f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}
			rc, err := f.Open()
			if err != nil {
				return err
			}
			outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				rc.Close()
				return err
			}
			if _, err := io.Copy(outFile, rc); err != nil {
				rc.Close()
				outFile.Close()
				return err
			}
			rc.Close()
			outFile.Close()
		}

		filled := int(float64(i+1) / float64(len(r.File)) * float64(barWidth))
		bar := fmt.Sprintf("\033[42m%s\033[0m%s", repeat(' ', filled), repeat(' ', barWidth-filled))
		percent := float64(i+1) / float64(len(r.File)) * 100
		fmt.Printf("\r\033[34m[+] Extracting ASN DB \033[0m[%s] \033[33m%.2f%%\033[0m", bar, percent)
	}

	fmt.Printf("\r\033[34m[+] Extracting ASN DB \033[0m[\033[42m%s\033[0m] \033[33m100.00%%\033[32m Extraction completed!\033[0m\n", repeat(' ', barWidth))

	moved := false
	masterDir := "asn-ip-master"
	files, _ := os.ReadDir(".")
	for _, f := range files {
		if f.IsDir() && strings.HasPrefix(f.Name(), "asn-ip") {
			masterDir = f.Name()
			break
		}
	}
	asSrc := filepath.Join(masterDir, "as")
	if _, err := os.Stat(asSrc); err == nil {

		if _, err := os.Stat(asnDataDir); err == nil {
			os.RemoveAll(asnDataDir)
		}
		if err := os.Rename(asSrc, asnDataDir); err != nil {
			return fmt.Errorf("failed to move ASN data: %v", err)
		}
		moved = true
	}

	os.Remove(zipPath)
	os.RemoveAll(masterDir)

	if !moved {
		return fmt.Errorf("failed to move ASN data")
	}

	fmt.Printf("\033[32m[+] ASN database ready.\033[0m\n")
	return nil
}

func repeat(char rune, n int) string {
	s := make([]rune, n)
	for i := 0; i < n; i++ {
		s[i] = char
	}
	return string(s)
}

func loadASN(asn string) (*ASNJSON, error) {
	asnNum := strings.TrimPrefix(strings.ToUpper(asn), "AS")
	jsonFile := filepath.Join(asnDataDir, asnNum, "aggregated.json")
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("ASN file not found for %s", asn)
	}
	var asnData ASNJSON
	if err := json.Unmarshal(data, &asnData); err != nil {
		return nil, err
	}
	return &asnData, nil
}

func lookupIP(ipStr string) (*ASNInfo, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		ips, err := net.LookupIP(ipStr)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("cannot resolve domain")
		}
		ip = ips[0]
		ipStr = ip.String()
	}
	asnDirs, err := os.ReadDir(asnDataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read asn-ip folder: %v", err)
	}
	for _, d := range asnDirs {
		if !d.IsDir() {
			continue
		}
		asnData, err := loadASN(d.Name())
		if err != nil {
			continue
		}
		for _, subnet := range append(asnData.Subnets.IPv4, asnData.Subnets.IPv6...) {
			_, cidr, err := net.ParseCIDR(subnet)
			if err != nil {
				continue
			}
			if cidr.Contains(ip) {
				return &ASNInfo{
					Query:       ipStr,
					IP:          ipStr,
					ASN:         fmt.Sprintf("AS%d", asnData.ASN),
					Description: asnData.Description,
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("IP not found in local DB")
}

func fetchURL(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	text := string(data)
	if strings.Contains(text, "API count exceeded") {
		return nil, fmt.Errorf("API limit reached")
	}
	if strings.Contains(text, "error") || strings.Contains(text, "Unable") {
		return nil, fmt.Errorf("API error: %s", text)
	}
	return data, nil
}

func ip2asnAPI(query string) (*ASNInfo, error) {
	ip := query
	if net.ParseIP(query) == nil {
		ips, err := net.LookupIP(query)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("cannot resolve domain")
		}
		ip = ips[0].String()
	}
	url := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=%s", ip)
	data, err := fetchURL(url)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.Trim(string(data), "\n"), ",")
	if len(parts) < 4 {
		return nil, fmt.Errorf("unexpected response")
	}
	return &ASNInfo{
		Query:       query,
		IP:          ip,
		ASN:         "AS" + strings.Trim(parts[1], "\""),
		Description: strings.Trim(parts[3], "\""),
	}, nil
}

func asn2ipsAPI(asn string) (*ASNInfo, error) {
	asn = strings.ToUpper(strings.TrimSpace(asn))
	if !strings.HasPrefix(asn, "AS") {
		asn = "AS" + asn
	}
	url := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=%s", asn)
	data, err := fetchURL(url)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.Trim(string(data), "\n"), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("unexpected response")
	}
	asnLine := strings.Split(lines[0], ",")
	if len(asnLine) < 2 {
		return nil, fmt.Errorf("unexpected response")
	}
	return &ASNInfo{
		Query:       asn,
		ASN:         asn,
		Description: strings.Trim(asnLine[1], "\""),
		Prefixes:    lines[1:],
	}, nil
}

func printText(info *ASNInfo, showPrefixes bool) {
	if isTerminal() {
		fmt.Printf("%sQuery:%s %s\n", cyan, reset, info.Query)
		if info.IP != "" {
			fmt.Printf("  %sResolved IP:%s %s\n", yellow, reset, info.IP)
		}
		fmt.Printf("  %sASN:%s %s\n", green, reset, info.ASN)
		fmt.Printf("  %sDescription:%s %s\n", cyan, reset, info.Description)
		if showPrefixes && len(info.Prefixes) > 0 {
			fmt.Printf("  %sPrefixes:%s\n", yellow, reset)
			for i, p := range info.Prefixes {
				if i%2 == 0 {
					fmt.Printf("    %-35s", p)
				} else {
					fmt.Printf("%s\n", p)
				}
			}
			if len(info.Prefixes)%2 != 0 {
				fmt.Printf("\n")
			}
		}
		return
	}

	fmt.Printf("Query: %s\n", info.Query)
	if info.IP != "" {
		fmt.Printf("  Resolved IP: %s\n", info.IP)
	}
	fmt.Printf("  ASN: %s\n", info.ASN)
	fmt.Printf("  Description: %s\n", info.Description)
	if showPrefixes && len(info.Prefixes) > 0 {
		fmt.Printf("  Prefixes:\n")
		for i, p := range info.Prefixes {
			if i%2 == 0 {
				fmt.Printf("    %-35s", p)
			} else {
				fmt.Printf("%s\n", p)
			}
		}
		if len(info.Prefixes)%2 != 0 {
			fmt.Printf("\n")
		}
	}
}

func printJSON(info *ASNInfo, outFile string) error {
	data, _ := json.MarshalIndent(info, "", "  ")
	if outFile != "" {
		return os.WriteFile(outFile, data, 0644)
	}
	if isTerminal() {
		s := string(data)
		s = strings.ReplaceAll(s, `"query":`, cyan+`"query":`+reset)
		s = strings.ReplaceAll(s, `"ip":`, cyan+`"ip":`+reset)
		s = strings.ReplaceAll(s, `"asn":`, cyan+`"asn":`+reset)
		s = strings.ReplaceAll(s, `"description":`, cyan+`"description":`+reset)
		s = strings.ReplaceAll(s, `"prefixes":`, cyan+`"prefixes":`+reset)
		fmt.Println(s)
		return nil
	}
	fmt.Println(string(data))
	return nil
}

func printCSV(info *ASNInfo, showPrefixes bool, outFile string) error {

	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			return err
		}
		defer f.Close()
		w := csv.NewWriter(f)
		if info.IP != "" && !showPrefixes {
			_ = w.Write([]string{"Query", "IP", "ASN", "Description"})
			_ = w.Write([]string{info.Query, info.IP, info.ASN, info.Description})
		} else if showPrefixes {
			_ = w.Write([]string{"ASN", "Description", "Prefix"})
			for _, p := range info.Prefixes {
				_ = w.Write([]string{info.ASN, info.Description, p})
			}
		} else {
			_ = w.Write([]string{"Query", "ASN", "Description"})
			_ = w.Write([]string{info.Query, info.ASN, info.Description})
		}
		w.Flush()
		return w.Error()
	}

	if isTerminal() {

		if info.IP != "" && !showPrefixes {
			fmt.Printf("%sQuery%s,%sIP%s,%sASN%s,%sDescription%s\n",
				cyan, reset, cyan, reset, yellow, reset, green, reset)
			fmt.Printf("%s%s%s,%s%s%s,%s%s%s,%s%s%s\n",
				cyan, info.Query, reset,
				yellow, info.IP, reset,
				yellow, info.ASN, reset,
				green, info.Description, reset)
			return nil
		}
		if showPrefixes {
			fmt.Printf("%sASN%s,%sDescription%s,%sPrefix%s\n",
				yellow, reset, green, reset, cyan, reset)
			for _, p := range info.Prefixes {
				fmt.Printf("%s%s%s,%s%s%s,%s%s%s\n",
					yellow, info.ASN, reset,
					green, info.Description, reset,
					cyan, p, reset)
			}
			return nil
		}

		fmt.Printf("%sQuery%s,%sASN%s,%sDescription%s\n",
			cyan, reset, yellow, reset, green, reset)
		fmt.Printf("%s%s%s,%s%s%s,%s%s%s\n",
			cyan, info.Query, reset,
			yellow, info.ASN, reset,
			green, info.Description, reset)
		return nil
	}

	w := csv.NewWriter(os.Stdout)
	if info.IP != "" && !showPrefixes {
		_ = w.Write([]string{"Query", "IP", "ASN", "Description"})
		_ = w.Write([]string{info.Query, info.IP, info.ASN, info.Description})
	} else if showPrefixes {
		_ = w.Write([]string{"ASN", "Description", "Prefix"})
		for _, p := range info.Prefixes {
			_ = w.Write([]string{info.ASN, info.Description, p})
		}
	} else {
		_ = w.Write([]string{"Query", "ASN", "Description"})
		_ = w.Write([]string{info.Query, info.ASN, info.Description})
	}
	w.Flush()
	return w.Error()
}

func printUsage() {

	fmt.Fprintf(os.Stderr, "%sUsage:%s\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "  ./asn_scanner [options]\n\n")
	fmt.Fprintf(os.Stderr, "%sOptions:%s\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "  %s--ip2asn%s    %sresolve IP or domain to ASN and info%s\n", yellow, reset, green, reset)
	fmt.Fprintf(os.Stderr, "  %s--asn2ips%s   %slist ranges for ASN or resolve domain -> ASN -> ranges%s\n", yellow, reset, green, reset)
	fmt.Fprintf(os.Stderr, "  %s--format%s    %soutput format: text, json, csv%s\n", yellow, reset, green, reset)
	fmt.Fprintf(os.Stderr, "  %s--output%s, %s-o%s   %soptional output file%s\n", yellow, reset, yellow, reset, green, reset)
	fmt.Fprintf(os.Stderr, "  %s--use-api%s   %suse hackertarget API instead of local DB%s\n", yellow, reset, green, reset)
	fmt.Fprintf(os.Stderr, "  %s--help%s      %sshow this help%s\n", yellow, reset, green, reset)
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot get home directory: %v\n", err)
		os.Exit(1)
	}
	asnDataDir = filepath.Join(home, ".cache", "asn_scanner_db")

	var ip2asnFlag string
	var asn2ipsFlag string
	var formatFlag string
	var outFile string
	var useAPI bool
	var help bool

	flag.StringVar(&ip2asnFlag, "ip2asn", "", "resolve IP or domain to ASN and info")
	flag.StringVar(&asn2ipsFlag, "asn2ips", "", "list ranges for ASN")
	flag.StringVar(&formatFlag, "format", "text", "output format: text, json, csv")
	flag.StringVar(&outFile, "output", "", "optional output file")
	flag.StringVar(&outFile, "o", "", "optional output file (shorthand)")
	flag.BoolVar(&useAPI, "use-api", false, "use hackertarget API instead of local DB")
	flag.BoolVar(&help, "help", false, "show help")
	flag.Usage = func() {
		printBannerAndMsg()
		printUsage()
	}
	flag.Parse()

	if help || (ip2asnFlag == "" && asn2ipsFlag == "") {
		printBannerAndMsg()
		printUsage()
		return
	}

	printBannerAndMsg()

	if err := ensureASNData(); err != nil {
		fmt.Fprintf(os.Stderr, "%sError setting up ASN data:%s %v\n", red, reset, err)
		os.Exit(1)
	}

	var info *ASNInfo
	showPrefixes := false

	if ip2asnFlag != "" {
		if useAPI {
			info, err = ip2asnAPI(ip2asnFlag)
		} else {
			info, err = lookupIP(ip2asnFlag)
		}
	} else if asn2ipsFlag != "" {
		showPrefixes = true
		if useAPI {
			info, err = asn2ipsAPI(asn2ipsFlag)
		} else {
			asnData, e := loadASN(asn2ipsFlag)
			if e != nil {
				fmt.Fprintf(os.Stderr, "%sError:%s %s\n", red, reset, e)
				os.Exit(1)
			}
			info = &ASNInfo{
				Query:       asn2ipsFlag,
				ASN:         fmt.Sprintf("AS%d", asnData.ASN),
				Description: asnData.Description,
				Prefixes:    append(asnData.Subnets.IPv4, asnData.Subnets.IPv6...),
			}
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError:%s %s\n", red, reset, err)
		os.Exit(1)
	}

	switch strings.ToLower(formatFlag) {
	case "text":
		printText(info, showPrefixes)
		if outFile != "" {
			data, _ := json.MarshalIndent(info, "", "  ")
			_ = os.WriteFile(outFile, data, 0644)
		}
	case "json":
		if err := printJSON(info, outFile); err != nil {
			fmt.Fprintf(os.Stderr, "%sError writing JSON:%s %v\n", red, reset, err)
			os.Exit(1)
		}
	case "csv":
		if err := printCSV(info, showPrefixes, outFile); err != nil {
			fmt.Fprintf(os.Stderr, "%sError writing CSV:%s %v\n", red, reset, err)
			os.Exit(1)
		}
	default:
		printText(info, showPrefixes)
	}

}
