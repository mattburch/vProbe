package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type status struct {
	stat string
	fin  bool
}

const (
	version = "0.0.1"
	tool    = "vProbe"
	usage   = `
Usage:
  vProbe [Options]
  vProbe -h | -help
  vProbe -v

Options:
  -h, -help              Show usage
  -v                     Show version
  -i                     Physical Interface [default: eth0]
  -r                     VLAN range (1-10)
  -t                     Threads [default: 10]

  -timeout               Timeout for command execution [default: 60]
`
	intconf = `
auto {int}.{sub}
iface {int}.{sub} inet static
  address 169.254.{net}.1
  netmask 255.255.255.252
`
)

func ifup(eth string, sub int) *status {
	vlan := fmt.Sprintf("%s.%s", eth, fmt.Sprintf("%v", sub))
	net := sub - (sub / 255 * 255)
	file := "/tmp/interface_" + vlan

	conf := strings.Replace(intconf, "{sub}", fmt.Sprintf("%v", sub), -1)
	conf = strings.Replace(conf, "{net}", fmt.Sprintf("%v", net), -1)
	conf = strings.Replace(conf, "{int}", eth, -1)

	err := ioutil.WriteFile(file, []byte(conf), 0655)
	if err != nil {
		return &status{
			stat: fmt.Sprintf("[*] Interface %s File Error: %v", vlan, err),
			fin:  false,
		}
	}

	ifup := exec.Command("ifup", "-i", file, vlan)
	if err := ifup.Run(); err != nil {
		return &status{
			stat: fmt.Sprintf("[*] Interface %s Start ERROR: %v", vlan, err),
			fin:  false,
		}
	}

	return &status{
		stat: fmt.Sprintf("[*] Interface %s started", vlan),
		fin:  false,
	}
}

func ifdown(eth string, sub int, end int) *status {
	vlan := fmt.Sprintf("%s.%s", eth, fmt.Sprintf("%v", sub))
	file := "/tmp/interface_" + vlan
	fin := false
	if sub == end {
		fin = true
	}

	ifdown := exec.Command("ifdown", "-i", file, vlan)
	err := ifdown.Run()
	if err != nil {
		return &status{
			stat: fmt.Sprintf("[*] Interface %s Stop ERROR: %v", vlan, err),
			fin:  fin,
		}
	}

	return &status{
		stat: fmt.Sprintf("[*] Interface %s: Shutdown", vlan),
		fin:  fin,
	}
}

func execLogging(r io.Reader, ch chan string, re *regexp.Regexp) {
	buf := make([]byte, 1024, 1024)
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			d := buf[:n]
			if stat := re.FindString(string(d)); stat != "" {
				ch <- stat
			}
		}
		if err == io.EOF {
			ch <- ""
			break
		}
	}
}

func dhcpscan(eth string, sub int, timeout string) *status {
	vlan := fmt.Sprintf("%s.%s", eth, fmt.Sprintf("%v", sub))
	ch := make(chan string)
	re := regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)

	cmd := exec.Command("timeout", timeout, "dhclient", "-v", vlan)
	stderrIn, _ := cmd.StderrPipe()

	cmd.Start()
	go execLogging(stderrIn, ch, regexp.MustCompile("DHCPACK.*?\n"))
	stat := <-ch

	if stat != "" {
		return &status{
			stat: fmt.Sprintf("[+] Interface %s: Live (%s) - DHCP", vlan, re.FindStringSubmatch(stat)[0]),
			fin:  false,
		}
	}
	return &status{
		stat: fmt.Sprintf("[-] Interface %s: Failed - DHCP", vlan),
		fin:  false,
	}

}

func arpscan(eth string, sub int, timeout string) *status {
	vlan := fmt.Sprintf("%s.%s", eth, fmt.Sprintf("%v", sub))
	ch := make(chan string)
	re := regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)

	cmd := exec.Command("timeout", timeout, "tcpdump", "-lnni", vlan)
	stderrIn, _ := cmd.StderrPipe()

	cmd.Start()
	go execLogging(stderrIn, ch, regexp.MustCompile("ARP, Reply.*?\n"))
	stat := <-ch

	if stat != "" {
		return &status{
			stat: fmt.Sprintf("[+] Interface %s: Live (%s) - ARP", vlan, re.FindStringSubmatch(stat)[0]),
			fin:  false,
		}
	}
	return &status{
		stat: fmt.Sprintf("[-] Interface %s: Failed - ARP", vlan),
		fin:  false,
	}

}

func main() {
	var (
		flVersion = flag.Bool("v", false, "")
		flInt     = flag.String("i", "eth0", "")
		flRange   = flag.String("r", "", "")
		flTimeout = flag.String("timeout", "60", "")
		flThread  = flag.Int("t", 10, "")
	)

	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	if *flVersion {
		fmt.Printf("version: %s\n", version)
		os.Exit(0)
	}
	if *flRange == "" {
		fmt.Errorf("Incorrect Range Provided\n")
		fmt.Println(usage)
		os.Exit(0)
	}

	r := strings.Split(*flRange, "-")
	start, _ := strconv.Atoi(r[0])
	end, _ := strconv.Atoi(r[1])

	ch := make(chan *status)
	thread := make(chan int, *flThread)
	go func() {
		for i := start; i <= end; i++ {
			thread <- i

			go func(i int) {
				ch <- ifup(*flInt, i)

				ch <- dhcpscan(*flInt, i, *flTimeout)
				ch <- arpscan(*flInt, i, *flTimeout)

				ch <- ifdown(*flInt, i, end)

				<-thread
			}(i)
		}
	}()

	for {
		stat := <-ch
		fmt.Println(stat.stat)
		if stat.fin {
			break
		}
	}
}
