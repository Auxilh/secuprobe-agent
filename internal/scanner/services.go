package scanner

import (
	"regexp"
	"strings"
)

// ServiceInfo is a service detected on an open port, with an optional product
// and version parsed from its banner. The backend correlates (product, version)
// against the CVE database.
type ServiceInfo struct {
	Port    int    `json:"port"`
	Name    string `json:"name"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
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

// bannerPattern maps a product (as named in NVD CPEs) to a regex capturing its
// version from a service banner. Keep products conservative: a missing match
// means no CVE correlation, which is better than a wrong one.
var bannerPatterns = []struct {
	product string
	re      *regexp.Regexp
}{
	{"openssh", regexp.MustCompile(`(?i)OpenSSH[_/ ]([0-9]+\.[0-9]+(?:p[0-9]+)?)`)},
	{"nginx", regexp.MustCompile(`(?i)nginx/([0-9]+\.[0-9]+\.[0-9]+)`)},
	{"http_server", regexp.MustCompile(`(?i)Apache/([0-9]+\.[0-9]+\.[0-9]+)`)},
	{"vsftpd", regexp.MustCompile(`(?i)vsftpd ([0-9]+\.[0-9]+\.[0-9]+)`)},
	{"proftpd", regexp.MustCompile(`(?i)ProFTPD ([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)},
	{"pure-ftpd", regexp.MustCompile(`(?i)Pure-FTPd`)},
	{"mysql", regexp.MustCompile(`(?i)([0-9]+\.[0-9]+\.[0-9]+)-.*MariaDB|mysql_native`)},
	{"postgresql", regexp.MustCompile(`(?i)PostgreSQL ([0-9]+\.[0-9]+)`)},
	{"exim", regexp.MustCompile(`(?i)Exim ([0-9]+\.[0-9]+)`)},
	{"postfix", regexp.MustCompile(`(?i)Postfix`)},
	{"dovecot", regexp.MustCompile(`(?i)Dovecot`)},
	{"redis", regexp.MustCompile(`(?i)redis_version:([0-9]+\.[0-9]+\.[0-9]+)`)},
}

// IdentifyServices turns open ports into labelled services, parsing the banner
// for a product and version where a conservative pattern matches.
func IdentifyServices(ports []OpenPort) []ServiceInfo {
	services := make([]ServiceInfo, 0, len(ports))
	for _, p := range ports {
		svc := ServiceInfo{Port: p.Port, Name: defaultPortNames[p.Port]}
		if svc.Name == "" {
			svc.Name = "unknown"
		}
		banner := strings.TrimSpace(p.Banner)
		if banner != "" {
			for _, bp := range bannerPatterns {
				m := bp.re.FindStringSubmatch(banner)
				if m == nil {
					continue
				}
				svc.Product = bp.product
				if len(m) > 1 && m[1] != "" {
					svc.Version = m[1]
				}
				break
			}
		}
		services = append(services, svc)
	}
	return services
}
