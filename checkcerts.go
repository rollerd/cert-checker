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
	NotBefore time.Time `json:"notbefore"`
	NotAfter  time.Time `json:"notafter"`
}

func main() {

	var serverList ServerList
	hostList := readHostList() // get list of IPs from file

	ch := make(chan Server, len(hostList)) // create channel for go routines to send completed Server types back to

	var wg sync.WaitGroup // wait group to allow go routines to finish
	wg.Add(len(hostList))

	for _, v := range hostList {
		go checkServerStatus(v, &wg, ch) // run server connectivity checks and build Server objects
	}

	for i := 0; i < len(hostList); i++ {
		serverList.Servers = append(serverList.Servers, <-ch) // pull Server objects from the channel into array
	}

	close(ch)

	wg.Wait()

	getCertificateStatus(&serverList) // set the status of Server objects based on cert Issue and Expire dates

	sendSlackMessage(serverList) //send messages to slack
}

func readHostList() []string {
	// read in the list of IPs from file
	var hostList []string

	file, err := os.Open("ip_addresses.txt")
	if err != nil {
		log.Fatal("ERROR: Could not open ip address file: ", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		hostList = append(hostList, scanner.Text())
	}

	return hostList
}

func checkServerStatus(ipAddress string, wg *sync.WaitGroup, ch chan Server) {
	// go routine for checking connectivity and getting cert data
	defer wg.Done()

	var server Server
	server.IP = ipAddress

	// create ip:port string for connection
	targetHost := fmt.Sprintf("%s:%s", ipAddress, "443")

	// set timeout so we don't hang on bad connections
	timeout, _ := time.ParseDuration("5s")
	conn, err := net.DialTimeout("tcp", targetHost, timeout)
	if err != nil {
		errorLogger.Printf("Could not create connection to '%s'", targetHost)
		server.Status = "errored"
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
		ch <- server
		return
	}

	// server can be reached and handshake complete - set status to good
	server.Status = "good"
	// set notbefore and notafter fields for server based on cert values
	server.NotBefore = client.ConnectionState().PeerCertificates[0].NotBefore
	server.NotAfter = client.ConnectionState().PeerCertificates[0].NotAfter
	ch <- server
}

func getCertificateStatus(serverList *ServerList) {
	currentTime := time.Now()
	for i := range serverList.Servers {
		if serverList.Servers[i].Status != "errored" {
			sevenDaysAgo := serverList.Servers[i].NotAfter.Add(-168 * time.Hour)
			thirtyDaysAgo := serverList.Servers[i].NotAfter.Add(-720 * time.Hour)
			switch {
			case (currentTime.After(serverList.Servers[i].NotAfter)):
				serverList.Servers[i].Status = "expired"
			case (currentTime.After(sevenDaysAgo)):
				serverList.Servers[i].Status = "seven_days"
			case (currentTime.After(thirtyDaysAgo)):
				serverList.Servers[i].Status = "thirty_days"
			}
		}
	}
}

func sendSlackMessage(serverList ServerList) {
	// arrays to hold the ips of servers based on status
	errored := []string{}
	sevenDays := []string{}
	thirtyDays := []string{}
	expired := []string{}
	good := []string{}

	// add the server ips to the correct arrays based on Server.Status
	for i := 0; i < len(serverList.Servers); i++ {
		status := serverList.Servers[i].Status
		serverIp := serverList.Servers[i].IP
		switch status {
		case "errored":
			errored = append(errored, serverIp)
		case "seven_days":
			sevenDays = append(sevenDays, serverIp)
			warnLogger.Printf("cert for '%s' is expiring very soon (<7 days til expiration)", serverIp)
		case "thirty_days":
			thirtyDays = append(thirtyDays, serverIp)
			warnLogger.Printf("cert for '%s' is expiring (<30 days til expiration)", serverIp)
		case "expired":
			expired = append(expired, serverIp)
			warnLogger.Printf("cert for '%s' is expired", serverIp)
		case "good":
			good = append(good, serverIp)
			infoLogger.Printf("cert for '%s' is good", serverIp)
		}
	}

	infoLogger.Printf("GOOD: %v\n", good)
	infoLogger.Printf("SEVENDAYS: %v\n", sevenDays)
	infoLogger.Printf("THIRTYDAYS: %v\n", thirtyDays)
	infoLogger.Printf("EXPIRED: %v\n", expired)
	infoLogger.Printf("ERRORED: %v\n", errored)

	// could also move these to separate template files
	// sevenDays
	if len(sevenDays) > 0 {
		sevenDaysMessage := fmt.Sprintf(`
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
		}`, strings.Join(sevenDays, "*\\n*"))
		sevenDaysJsonMessage := []byte(sevenDaysMessage)
		postToSlack(sevenDaysJsonMessage)
	}

	// thirtyDays
	if len(thirtyDays) > 0 {
		thirtyDaysMessage := fmt.Sprintf(`
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
		}`, strings.Join(thirtyDays, "*\\n*"))
		thirtyDaysJsonMessage := []byte(thirtyDaysMessage)
		postToSlack(thirtyDaysJsonMessage)
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
