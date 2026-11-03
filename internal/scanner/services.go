package scanner

import (
	"regexp"
	"strings"
)

// Identification says how a service name was obtained (audit F69).
const (
	// IdentifiedByBanner: the banner names the product.
	IdentifiedByBanner = "banner"
	// IdentifiedByPort: only the port number suggests the service ("usual
	// port of ..."); nothing confirms it.
	IdentifiedByPort = "port"
	// Unidentified: neither the banner nor the port suggest a service.
	Unidentified = "none"
)

// ServiceInfo is a service detected on an open port, with an optional product
// and version parsed from its banner. The backend correlates (product, version)
// against the CVE database; such a match is a candidate to verify, not a proof.
type ServiceInfo struct {
	Port           int    `json:"port"`
	Name           string `json:"name"`
	Product        string `json:"product,omitempty"`
	Version        string `json:"version,omitempty"`
	Identification string `json:"identification"`
}

// defaultPortNames labels well-known ports when the banner is silent.
var defaultPortNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
	143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
	993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
	3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
	8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

// bannerPatterns maps a product (as named in NVD CPEs) to a regex capturing its
// version from a service banner, and the service the product implies. Keep
// products conservative: a missing match means no CVE correlation, which is
// better than a wrong one.
var bannerPatterns = []struct {
	product string
	service string
	re      *regexp.Regexp
}{
	{"openssh", "ssh", regexp.MustCompile(`(?i)OpenSSH[_/ ]([0-9]+\.[0-9]+(?:p[0-9]+)?)`)},
	{"nginx", "http", regexp.MustCompile(`(?i)nginx/([0-9]+\.[0-9]+\.[0-9]+)`)},
	{"http_server", "http", regexp.MustCompile(`(?i)Apache/([0-9]+\.[0-9]+\.[0-9]+)`)},
	{"vsftpd", "ftp", regexp.MustCompile(`(?i)vsftpd ([0-9]+\.[0-9]+\.[0-9]+)`)},
	{"proftpd", "ftp", regexp.MustCompile(`(?i)ProFTPD ([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)},
	{"pure-ftpd", "ftp", regexp.MustCompile(`(?i)Pure-FTPd`)},
	// MariaDB announces "5.5.5-<version>-MariaDB": it is not MySQL and has its own CVEs.
	{"mariadb", "mysql", regexp.MustCompile(`(?i)(?:5\.5\.5-)?([0-9]+\.[0-9]+\.[0-9]+)-[^\x00]*MariaDB`)},
	{"postgresql", "postgresql", regexp.MustCompile(`(?i)PostgreSQL ([0-9]+\.[0-9]+)`)},
	{"exim", "smtp", regexp.MustCompile(`(?i)Exim ([0-9]+\.[0-9]+)`)},
	{"postfix", "smtp", regexp.MustCompile(`(?i)Postfix`)},
	{"dovecot", "imap", regexp.MustCompile(`(?i)Dovecot`)},
	{"redis", "redis", regexp.MustCompile(`(?i)redis_version:([0-9]+\.[0-9]+\.[0-9]+)`)},
}

var mysqlVersion = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)`)

// mysqlHandshake reads the server version of a MySQL protocol handshake
// (4-byte packet header, protocol version 10, null-terminated version).
func mysqlHandshake(banner string) (string, bool) {
	if len(banner) < 6 || banner[4] != 0x0a {
		return "", false
	}
	rest := banner[5:]
	end := strings.IndexByte(rest, 0)
	if end < 0 {
		return "", false
	}
	m := mysqlVersion.FindStringSubmatch(rest[:end])
	if m == nil {
		return "", false
	}
	return m[1], true
}

// IdentifyServices turns open ports into labelled services, parsing the banner
// for a product and version where a conservative pattern matches. Without a
// banner match the name only reflects the usual service of the port.
func IdentifyServices(ports []OpenPort) []ServiceInfo {
	services := make([]ServiceInfo, 0, len(ports))
	for _, p := range ports {
		svc := ServiceInfo{Port: p.Port, Name: defaultPortNames[p.Port], Identification: IdentifiedByPort}
		if svc.Name == "" {
			svc.Name = "unknown"
			svc.Identification = Unidentified
		}
		banner := strings.TrimSpace(p.Banner)
		matched := false
		if banner != "" {
			for _, bp := range bannerPatterns {
				m := bp.re.FindStringSubmatch(banner)
				if m == nil {
					continue
				}
				svc.Product, svc.Name, svc.Identification = bp.product, bp.service, IdentifiedByBanner
				if len(m) > 1 && m[1] != "" {
					svc.Version = m[1]
				}
				matched = true
				break
			}
		}
		if !matched {
			// Untrimmed banner: the handshake starts with binary bytes.
			if v, ok := mysqlHandshake(p.Banner); ok {
				svc.Product, svc.Name, svc.Version, svc.Identification = "mysql", "mysql", v, IdentifiedByBanner
			}
		}
		services = append(services, svc)
	}
	return services
}
