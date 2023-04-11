package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const SLACKWEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" // could move this to env var

var errorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
var warnLogger = log.New(os.Stderr, "WARN: ", log.Ldate|log.Ltime|log.Lshortfile)
var infoLogger = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

type ServerList struct {
	Servers []Server
}

type Server struct {
	IP        string    `json:"ipaddress"`
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	NotBefore time.Time `json:"notbefore"`
	NotAfter  time.Time `json:"notafter"`
}

func main() {

	var serverList ServerList
	ipList := readIpList() // get list of IPs from file

	ch := make(chan Server, len(ipList)) // create channel for go routines to send completed Server types back to

	var wg sync.WaitGroup // wait group to allow go routines to finish
	wg.Add(len(ipList))

	for _, v := range ipList {
		go checkServerStatus(v, &wg, ch) // run server connectivity checks and build Server objects
	}

	for i := 0; i < len(ipList); i++ {
		serverList.Servers = append(serverList.Servers, <-ch) // pull Server objects from the channel into array
	}

	close(ch)

	wg.Wait()

	getCertificateStatus(&serverList) // set the status of Server objects based on cert Issue and Expire dates

	sendSlackMessage(serverList) //send messages to slack
}

func parseCidr(cidr string) *net.IPNet {
	// used for initially parsing the service network CIDRs
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal("ERROR: Could not initialize subnets")
	}

	return ipNet
}

func readIpList() []string {
	// read in the list of IPs from file
	var ipList []string

	file, err := os.Open("ip_addresses.txt")
	if err != nil {
		log.Fatal("ERROR: Could not open ip address file: ", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		ipList = append(ipList, scanner.Text())
	}

	return ipList
}

func checkServerStatus(ipAddress string, wg *sync.WaitGroup, ch chan Server) {
	// go routine for checking connectivity and getting cert data
	defer wg.Done()

	var server Server
	server.IP = ipAddress

	if targetPort == "" {
		server.Status = "errored"
		server.Service = "unknown"
		ch <- server
		return
	}

	// create ip:port string for connection
	targetHost := fmt.Sprintf("%s:%s", ipAddress, targetPort)

	// set timeout so we don't hang on bad connections
	timeout, _ := time.ParseDuration("5s")
	conn, err := net.DialTimeout("tcp", targetHost, timeout)
	if err != nil {
		errorLogger.Printf("Could not create connection to '%s'", targetHost)
		server.Status = "errored"
		server.Service = service
		ch <- server
		return
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	client := tls.Client(conn, tlsCfg)

	// manually start handshake to get cert
	err = client.Handshake()
	if err != nil {
		errorLogger.Printf("Could not complete handshake to '%s'", targetHost)
		server.Status = "errored"
		server.Service = service
		ch <- server
		return
	}

	// server can be reached and handshake complete - set status to good
	server.Status = "good"
	server.Service = service
	// set notbefore and notafter fields for server based on cert values
	server.NotBefore = client.ConnectionState().PeerCertificates[0].NotBefore
	server.NotAfter = client.ConnectionState().PeerCertificates[0].NotAfter
	ch <- server
}

func getCertificateStatus(serverList *ServerList) {
	// take array of non-connection error Servers and determine status of certificate expiration
	for i := 0; i < len(serverList.Servers); i++ {
		if serverList.Servers[i].Status != "errored" {
			currentTime := time.Now()
			// check if cert was issued in past 7 days - assume NotBefore is the actual issue/deploy date
			prevWeek := currentTime.Add(-168 * time.Hour)
			if serverList.Servers[i].NotBefore.Before(prevWeek) {
				serverList.Servers[i].Status = "outdated"
			}
			// check if cert expires within the next 30 days
			thirtyDays := serverList.Servers[i].NotAfter.Add(-720 * time.Hour)
			if currentTime.After(thirtyDays) {
				serverList.Servers[i].Status = "expiring"
			}
			// check if cert is already expired
			if currentTime.After(serverList.Servers[i].NotAfter) {
				serverList.Servers[i].Status = "expired"
			}
		}
	}
}

func sendSlackMessage(serverList ServerList) {
	// arrays to hold the ips of servers based on status
	outdated := []string{}
	expiring := []string{}
	expired := []string{}
	errored := []string{}
	good := []string{}

	// add the server ips to the correct arrays based on Server.Status
	for i := 0; i < len(serverList.Servers); i++ {
		status := serverList.Servers[i].Status
		serverIp := serverList.Servers[i].IP
		switch status {
		case "outdated":
			outdated = append(outdated, serverIp)
			warnLogger.Printf("cert for '%s' is outdated (>7 days since re-issue)", serverIp)
		case "expiring":
			expiring = append(expiring, serverIp)
			warnLogger.Printf("cert for '%s' is expiring (<30 days til expiration)", serverIp)
		case "expired":
			expired = append(expired, serverIp)
			warnLogger.Printf("cert for '%s' is expired", serverIp)
		case "errored":
			errored = append(errored, serverIp)
		case "good":
			good = append(good, serverIp)
			infoLogger.Printf("cert for '%s' is good", serverIp)
		}
	}

	infoLogger.Printf("GOOD: %v\n", good)
	infoLogger.Printf("OUTDATED: %v\n", outdated)
	infoLogger.Printf("EXPIRING: %v\n", expiring)
	infoLogger.Printf("EXPIRED: %v\n", expired)
	infoLogger.Printf("ERRORED: %v\n", errored)

	// could also move these to separate template files
	// outdated
	if len(outdated) > 0 {
		outdatedMessage := fmt.Sprintf(`
		{
		"blocks": [
			{
				"type": "section",
				"text": {
					"type": "plain_text",
					"emoji": true,
					"text": "The following servers have certificates that have not been updated in the last 7 days:"
				}
			},
			{
				"type": "divider"
			},
			{
				"type": "section",
				"text": {
					"type": "mrkdwn",
					"text": "*%s*"
				}
			}
		]
		}`, strings.Join(outdated, "*\\n*"))
		outdatedJsonMessage := []byte(outdatedMessage)
		postToSlack(outdatedJsonMessage)
	}

	// expiring
	if len(expiring) > 0 {
		expiringMessage := fmt.Sprintf(`
		{
		"blocks": [
			{
				"type": "section",
				"text": {
					"type": "mrkdwn",
					"text": "*URGENT* Certificates are about to expire for the following servers (<30 days):"
				}
			},
			{
				"type": "divider"
			},
			{
				"type": "section",
				"text": {
					"type": "mrkdwn",
					"text": "*%s*"
				},
				"accessory": {
					"type": "image",
					"image_url": "https://api.slack.com/img/blocks/bkb_template_images/notificationsWarningIcon.png",
					"alt_text": "warning"
				}
			}
		]
		}`, strings.Join(expiring, "*\\n*"))
		expiringJsonMessage := []byte(expiringMessage)
		postToSlack(expiringJsonMessage)
	}

	// expired
	if len(expired) > 0 {
		expiredMessage := fmt.Sprintf(`
		{
		"blocks": [
			{
				"type": "section",
				"text": {
					"type": "mrkdwn",
					"text": "*EXTREMELY URGENT* Certificates have expired for the following servers:"
				}
			},
			{
				"type": "divider"
			},
			{
				"type": "section",
				"text": {
					"type": "mrkdwn",
					"text": "*%s*"
				},
				"accessory": {
					"type": "image",
					"image_url": "https://api.slack.com/img/blocks/bkb_template_images/notificationsWarningIcon.png",
					"alt_text": "warning"
				}
			}
		]
		}`, strings.Join(expired, "*\\n*"))
		expiredJsonMessage := []byte(expiredMessage)
		postToSlack(expiredJsonMessage)
	}

	// errored
	if len(errored) > 0 {
		erroredMessage := fmt.Sprintf(`
		{
		"blocks": [
			{
				"type": "section",
				"text": {
					"type": "plain_text",
					"emoji": true,
					"text": "The following servers were unreachable due to connection errors:"
				}
			},
			{
				"type": "divider"
			},
			{
				"type": "section",
				"text": {
					"type": "mrkdwn",
					"text": "*%s*"
				}
			}
		]
		}`, strings.Join(errored, "*\\n*"))
		erroredJsonMessage := []byte(erroredMessage)
		postToSlack(erroredJsonMessage)
	}
}

func postToSlack(message []byte) {
	request, err := http.NewRequest("POST", SLACKWEBHOOK, bytes.NewBuffer(message))
	if err != nil {
		errorLogger.Println("Could not build request for slack message: ", err)
	}

	request.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		errorLogger.Println("Could not send slack message: ", err)
	}
	defer response.Body.Close()
}
