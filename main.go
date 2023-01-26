package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/guptarohit/asciigraph"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe" // TODO get terminal size in a nicer way
	"strconv"
	"text/tabwriter"
)

var logFile = flag.String("logfile", "log.jsonl", "Logfile")
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var inFile = flag.String("input", "in.txt", "Text file with ip addresses")
var parallel = flag.Int("t", 40000, "Parallelism, must be smaller than: net.ipv4.ip_local_port_range (second value - first value)")
var port = flag.Int("p", 22, "SSH port")
var username = flag.String("user", "", "SSH user")
var password = flag.String("pass", "", "SSH password")
var command = flag.String("cmd", "id", "SSH command")
var srcIps = flag.String("src", "", "Comma separated list of source IP addresses to use")
var localAddrs []*net.TCPAddr
var logUser = flag.Bool("loguser", false, "Log user")
var logPass = flag.Bool("logpass", false, "Log password")
var loggedUser string = "-"
var loggedPass string = "-"
var interactivePass = flag.Bool("interactivepass", false, "Read password as console input")

type Stats struct {
	Mu                            sync.Mutex
	ActiveWorkers                 float64
	LinesRead                     float64
	ActiveTcpConnectionCount      float64
	ActiveSshConnectionCount      float64
	ActiveSshSessionCount         float64
	ActiveCmdRunCount             float64
	SuccessfullTcpConnectionCount float64
	SuccessfullSshConnectionCount float64
	SuccessfullSshSessionCount    float64
	SuccessfullCmdRunCount        float64
	FailedTcpConnectionCount      float64
	FailedSshConnectionCount      float64
	FailedSshSessionCount         float64
	FailedCmdRunCount             float64
}

func (s *Stats) Print() {
	fmt.Print("\n\n\n\n")
        w := new(tabwriter.Writer)
        // minwidth, tabwidth, padding, padchar, flags
        w.Init(os.Stdout, 20, 8, 0, '\t', 0)

        fmt.Fprintf(w, "\n %s\t%s\t%s\t%s\t%s", "Status", "TCP Connections", "SSH Connections", "SSH Sessions", "SSH Command")
	fmt.Fprintf(w, "\n %s\t%.0f\t%.0f\t%.0f\t%.0f", "Active", s.ActiveTcpConnectionCount, s.ActiveSshConnectionCount, s.ActiveSshSessionCount, s.ActiveCmdRunCount)
	fmt.Fprintf(w, "\n %s\t%.0f\t%.0f\t%.0f\t%.0f", "Failed", s.FailedTcpConnectionCount, s.FailedSshConnectionCount, s.FailedSshSessionCount, s.FailedCmdRunCount)
	fmt.Fprintf(w, "\n %s\t%.0f\t%.0f\t%.0f\t%.0f", "Success", s.SuccessfullTcpConnectionCount, s.SuccessfullSshConnectionCount, s.SuccessfullSshSessionCount, s.SuccessfullCmdRunCount)

	secs := time.Since(start).Seconds()
	tcpRate := (s.FailedTcpConnectionCount + s.SuccessfullTcpConnectionCount) / secs
	sshConnRate := (s.FailedSshConnectionCount + s.SuccessfullSshConnectionCount) / secs
	sshSessRate := (s.FailedSshSessionCount + s.SuccessfullSshSessionCount) / secs
	cmdRate := (s.FailedCmdRunCount + s.SuccessfullCmdRunCount) / secs
	fmt.Fprintf(w, "\n %s\t%.0f\t%.3f\t%.3f\t%.3f\n", "Rates", tcpRate, sshConnRate, sshSessRate, cmdRate)
        w.Flush()
}

var stats Stats
var start = time.Now()

const (
	kexAlgoDH1SHA1          = "diffie-hellman-group1-sha1"
	kexAlgoDH14SHA1         = "diffie-hellman-group14-sha1"
	kexAlgoECDH256          = "ecdh-sha2-nistp256"
	kexAlgoECDH384          = "ecdh-sha2-nistp384"
	kexAlgoECDH521          = "ecdh-sha2-nistp521"
	kexAlgoDHGEXSHA1        = "diffie-hellman-group-exchange-sha1"
	kexAlgoDHGEXSHA256      = "diffie-hellman-group-exchange-sha256"
        kexAlgoDH14SHA256             = "diffie-hellman-group14-sha256"
        kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org"
        kexAlgoCurve25519SHA256       = "curve25519-sha256"
)

//https://github.com/golang/crypto/blob/master/ssh/common.go
var supportedCiphers = []string{
	"aes128-ctr", "aes192-ctr", "aes256-ctr",
	"aes128-gcm@openssh.com",
	"arcfour256", "arcfour128", "arcfour",
	"aes128-cbc",
	"3des-cbc",
}


var supportedKexAlgos = []string{
	kexAlgoDH1SHA1, kexAlgoDH14SHA1, kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521, kexAlgoDHGEXSHA256, kexAlgoDH14SHA256, kexAlgoCurve25519SHA256LibSSH, kexAlgoCurve25519SHA256, kexAlgoDHGEXSHA1,
}

const maxHistorySize int = 256
var history []*Stats

func DoSearch() {
	wg := &sync.WaitGroup{}

	f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Error("Cannot open log file! Logging to Stdout")
		f = os.Stdout
	} else {
		log.WithFields(log.Fields{"logfile": *logFile}).Info("Logging (appending) to file")
	}

	lines := make(chan string)
	logger := &log.Logger{
		Out:       f,
		Formatter: &log.JSONFormatter{},
		Level:     log.TraceLevel,
	}

	for _, localAddr := range strings.Split(*srcIps, ",") {
		fmt.Println(localAddr)
		a := localAddr
		ip := net.ParseIP(a)
		for i := 0; i < *parallel; i++ {
			wg.Add(1)

			stats.Mu.Lock()
			stats.ActiveWorkers += 1
			stats.Mu.Unlock()
			go func() {
				for line := range lines {
					stats.Mu.Lock()
					stats.LinesRead += 1
					stats.Mu.Unlock()

					addr := &net.TCPAddr{
						IP: ip,
					}
					TestConnection(line, logger.WithFields(log.Fields{"user": loggedUser, "pass": loggedPass, "ip": line, "src": a}), addr)
				}
				stats.Mu.Lock()
				stats.ActiveWorkers -= 1
				stats.Mu.Unlock()

				wg.Done()
			}()
		}
	}

	fileHandle, _ := os.Open(*inFile)
	defer fileHandle.Close()

	go func() {
		fileScanner := bufio.NewScanner(fileHandle)

		for fileScanner.Scan() {
			lines <- fileScanner.Text()
		}

		logger.Info("Input file read complete")
		close(lines)
	}()

	go func() {
		for {
			stats.Mu.Lock()
			snapShot := stats
			stats.Mu.Unlock()

			history = append(history, &snapShot)
			if len(history) > maxHistorySize {
				history = history[1:]
			}

			data := []float64{}
			max := len(history)
			terminalWidth := int(getWidth())
			if max+12 > terminalWidth {
				max = terminalWidth - 12
			}
			for i := 0; i < max; i++ {
				data = append(data, history[i].ActiveSshSessionCount)
			}

			fmt.Print("\033[H\033[2J")
			fmt.Println(asciigraph.Plot(data, asciigraph.Height(23)))
			snapShot.Print()

			time.Sleep(500 * time.Millisecond)
		}
	}()

	wg.Wait()
}

func ServerVersionToString(serverVersionBytes []byte) string {
	if utf8.Valid(serverVersionBytes) {
		return string(serverVersionBytes)
	} else {
		return fmt.Sprintf("Invalid utf8 in server version: %x", serverVersionBytes)
	}
}

func TestConnection(host string, logger *log.Entry, localAddr *net.TCPAddr) {
	r := make(chan error)
	c := make(chan struct{})

	stats.Mu.Lock()
	stats.ActiveTcpConnectionCount += 1
	stats.Mu.Unlock()

	klingeling := net.Dialer{
		LocalAddr: localAddr,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	tcpConn, err := klingeling.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(*port)))
	defer func() {
		stats.Mu.Lock()
		stats.ActiveTcpConnectionCount -= 1
		stats.Mu.Unlock()
		if tcpConn != nil {
			tcpConn.Close()
		}
	}()

	if err != nil {
		stats.Mu.Lock()
		stats.FailedTcpConnectionCount += 1
		stats.Mu.Unlock()
		logger.Trace("TCP connection failed")
		return
	}

	stats.Mu.Lock()
	stats.SuccessfullTcpConnectionCount += 1
	stats.Mu.Unlock()

	var sshConnection ssh.Conn
	var sshClient *ssh.Client

	defer func() {
		stats.Mu.Lock()
		stats.ActiveSshConnectionCount -= 1
		stats.Mu.Unlock()
		if sshConnection != nil {

			sshConnection.Close()
		}
		if sshClient != nil {
			sshClient.Close()
		}
	}()

	go func() {
		sshClientConfig := &ssh.ClientConfig{
			User:    *username,
			Auth:    []ssh.AuthMethod{ssh.Password(*password)},
			Timeout: 12 * time.Second,
			Config: ssh.Config{
				KeyExchanges: supportedKexAlgos,
				Ciphers: supportedCiphers,
			},
		}

		sshClientConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			logger.WithFields(log.Fields{
				"fingerprint": ssh.FingerprintSHA256(key),
			}).Trace("Got host key")
			return nil
		}

		var (
			chans <-chan ssh.NewChannel
			reqs  <-chan *ssh.Request
		)

		stats.Mu.Lock()
		stats.ActiveSshConnectionCount += 1
		stats.Mu.Unlock()

		sshConnection, chans, reqs, err = ssh.NewClientConn(tcpConn, host, sshClientConfig)

		if sshConnection != nil {
			logger = logger.WithFields(log.Fields{
				"server": ServerVersionToString(sshConnection.ServerVersion()),
			})
		}

		if err != nil {
			stats.Mu.Lock()
			stats.FailedSshConnectionCount += 1
			stats.Mu.Unlock()

			logger.WithFields(log.Fields{
				"err": err,
			}).Trace("SSH Handshake failed")

			r <- err
			return
		}

		stats.Mu.Lock()
		stats.SuccessfullSshConnectionCount += 1
		stats.Mu.Unlock()

		logger.Info("SSH Handshake completed")
		sshClient = ssh.NewClient(sshConnection, chans, reqs)
		c <- struct{}{}
	}()

	select {
	case err = <-r:
		return
	case <-time.After(20 * time.Second):
		logger.Trace("Outer SSH Handshake Timeout")
		return
	case <-c:
		logger.Trace("Handshake completed")
	}

	r = make(chan error)
	var sshSession *ssh.Session
	if sshClient == nil {
		logger.Error("This should not occur")
		return
	}

	logger = logger.WithFields(log.Fields{
		"server": ServerVersionToString(sshClient.ServerVersion()),
	})

	defer func() {
		if sshSession != nil {
			stats.Mu.Lock()
			stats.ActiveSshSessionCount -= 1
			stats.Mu.Unlock()

			logger.Trace("Closing session")
			sshSession.Close()
		}
	}()

	c = make(chan struct{})

	go func() {
		stats.Mu.Lock()
		stats.ActiveSshSessionCount += 1
		stats.Mu.Unlock()

		sshSession, err = sshClient.NewSession()

		if err != nil {
			stats.Mu.Lock()
			stats.FailedSshSessionCount += 1
			stats.Mu.Unlock()
			logger.WithFields(log.Fields{
				"err": err,
			}).Trace("NewSession failed")

			r <- err
			return
		}

		stats.Mu.Lock()
		stats.SuccessfullSshSessionCount += 1
		stats.Mu.Unlock()

		c <- struct{}{}
	}()

	select {
	case err = <-r:
		logger.Trace(err)
		return
	case <-time.After(24 * time.Second):
		logger.Trace("NewSession timeout")
		return
	case <-c:
		logger.Trace("Session established")
	}

	out := make(chan string)
	go func() {
		stats.Mu.Lock()
		stats.ActiveCmdRunCount += 1
		stats.Mu.Unlock()

		res, err := sshSession.CombinedOutput(*command)
		if err != nil {
			stats.Mu.Lock()
			stats.FailedCmdRunCount += 1
			stats.Mu.Unlock()

			logger.WithFields(log.Fields{
				"err": err,
			}).Trace("CombinedOutput failed")

			r <- err
			return
		}
		stats.Mu.Lock()
		stats.SuccessfullCmdRunCount += 1
		stats.ActiveCmdRunCount -= 1
		stats.Mu.Unlock()

		if utf8.Valid(res) {
			out <- string(res)
		} else {
			out <- fmt.Sprintf("%x", res)
		}
	}()

	select {
	case err = <-r:
		stats.Mu.Lock()
		stats.ActiveCmdRunCount -= 1
		stats.Mu.Unlock()

		logger.Trace(err)
		return
	case <-time.After(20 * time.Second):
		stats.Mu.Lock()
		stats.ActiveCmdRunCount -= 1
		stats.Mu.Unlock()

		logger.Warn("Command exec timeout")
		return
	case msg := <-out:
		logger.WithFields(log.Fields{"msg": msg}).Info("Got reply")
	}
}

func getWidth() uint {
	type winsize struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}
	ws := &winsize{}
	retCode, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(syscall.Stdin),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(ws)))

	if int(retCode) == -1 {
		panic(errno)
	}
	return uint(ws.Col)
}

func setLimits() {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Println("Error Getting Rlimit ", err)
	}

	rLimit.Cur = rLimit.Max
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Println(err)
	}

	var rLimit2 syscall.Rlimit
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit2)
	if err != nil {
		fmt.Println("Error Getting Rlimit ", err)
	}
	log.Infof("RLIMIT_NOFILE is %d", rLimit2.Cur)
}

func main() {
	setLimits()
	flag.Parse()
	// Log user or pass
	if *logUser {
		loggedUser = *username
	}
	if *logPass {
		loggedPass = *password
	}
	// Read pass as console input
	if *interactivePass {
		fmt.Print("Password: ")
		input, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
		*password = string(input)
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		go func() {
			time.Sleep(10 * time.Second)
			pprof.StopCPUProfile()
		}()
	}

	for _, ip := range strings.Split(*srcIps, ",") {
		localAddrs = append(localAddrs, &net.TCPAddr{
			IP:   net.ParseIP(ip),
			Port: 0,
		})
	}
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
	DoSearch()
}
