# ASN Scanner

![ASN Scanner Demo](asst/preview.gif)  

**ASN Scanner** is a simple and fast tool to query ASN information, resolve IPs/domains to ASNs, and list prefixes. It can use __local ASN database__ for offline lookups or __Hackertarget API__ for quick online queries.

---

## Features

- Resolve **IP or domain → ASN**  
- List **all prefixes for a given ASN**  
- Output in **text**, **JSON**, or **CSV**  
- Colored terminal output for readability  
- Automatic download and extraction of ASN database for offline use  

---

## Installation

```bash
git clone https://github.com/VexilonHacker/asngo
cd asngo
go build -o asn_scanner main.go
```

---

## Basic usage

```bash
# Resolve an IP -> ASN
./asn_scanner --ip2asn 8.8.8.8

# Resolve an domain -> ASN 
./asn_scanner --ip2asn github.com 
```

## Output formats

```bash
# JSON output to file
./asn_scanner --ip2asn 8.8.8.8 --format json --output result.json

# CSV output of all prefixes for an ASN
./asn_scanner --asn2ips AS15169 --format csv --output prefixes.csv
```
## Help menu 
``` 

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

[+] Scan result follows below

Usage:
  ./asn_scanner [options]

Options:
  --ip2asn    resolve IP or domain to ASN and info
  --asn2ips   list ranges for ASN or resolve domain -> ASN -> ranges
  --format    output format: text, json, csv
  --output, -o   optional output file
  --use-api   use hackertarget API instead of local DB
  --help      show this help

```


## License

MIT © VexilonHacker

