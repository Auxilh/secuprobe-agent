package scanner

import "testing"

func TestIdentifyServicesParsesOpenSSH(t *testing.T) {
	svcs := IdentifyServices([]OpenPort{{Port: 22, Protocol: "tcp", Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu"}})
	if len(svcs) != 1 {
		t.Fatalf("got %d services", len(svcs))
	}
	s := svcs[0]
	if s.Name != "ssh" || s.Product != "openssh" || s.Version != "8.9p1" {
		t.Fatalf("got %+v", s)
	}
}

func TestIdentifyServicesParsesNginx(t *testing.T) {
	svcs := IdentifyServices([]OpenPort{{Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"}})
	if svcs[0].Product != "nginx" || svcs[0].Version != "1.18.0" {
		t.Fatalf("got %+v", svcs[0])
	}
}

func TestIdentifyServicesUnknownBannerKeepsPortName(t *testing.T) {
	svcs := IdentifyServices([]OpenPort{{Port: 3306, Banner: "\x00\x00\x00"}})
	if svcs[0].Name != "mysql" {
		t.Fatalf("expected mysql port name, got %+v", svcs[0])
	}
	if svcs[0].Product != "" {
		t.Fatalf("expected no product for unparsed banner, got %+v", svcs[0])
	}
}

func TestIdentifyServicesUnknownPort(t *testing.T) {
	svcs := IdentifyServices([]OpenPort{{Port: 54321}})
	if svcs[0].Name != "unknown" {
		t.Fatalf("got %+v", svcs[0])
	}
}
