package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	_ "encoding/hex"
	"errors"
	"flag"
	"fmt"
	mysql "github.com/go-sql-driver/mysql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	MySQLProtocol "github.com/linkedin/QueryAnalyzerAgent/databases"
	"github.com/spf13/viper"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	_ "regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config struct to hold various sections of the config
type Config struct {
	Sniffer  snifferConfig  `mapstructure:"sniffer"`
	QanAgent qanAgentConfig `mapstructure:"qan-agent"`
	LocalDB  localDBConfig  `mapstructure:"localDB"`
	RemoteDB remoteDBConfig `mapstructure:"remoteDB"`
}

// Config struct to hold sniffer config section
type snifferConfig struct {
	ListenInterface     string
	ListenPort          uint16
	CaptureLength       int32
	ReportStatsInterval int32
	IgnoreIPs           string
}

// Config struct to hold qan agent config section
type qanAgentConfig struct {
	ReportInterval   uint32
	MaxRequestLength uint32
	MaxDBConnections int
	DebugLevels      string
	LogFile          string
	DebugMap         map[uint8]bool
}

// Config struct to hold config related to connecting to local db
type localDBConfig struct {
	LocalUsername string
	LocalPassword string
	LocalSocket   string
	Enabled       uint8
}

// Config struct to hold config related to connecting to remote db
type remoteDBConfig struct {
	Hostname      string
	Port          uint16
	Username      string
	Password      string
	DBName        string
	Ca_cert       string
	Client_cert   string
	Client_key    string
	Enabled       uint8
	SSLEnabled    uint8
	IncludeSample uint8
}

// struct for query information
type queryInfo struct {
	checksum    string
	src         string
	user        string
	db          string
	fingerprint string
	sample      string
	queryTime   float64
	minTime     float64
	maxTime     float64
	count       uint32
	bytesIn     uint32
}

// struct for query metadata information
type queryMeta struct {
	checksum string
	minTime  float64
	maxTime  float64
}

// hashmap for query info
var queryInfoMap map[string]*queryInfo = make(map[string]*queryInfo)
var queryInfoCopyMap map[string]*queryInfo = make(map[string]*queryInfo)

// hashmap for query metadata info
var queryMetaMap map[string]*queryMeta = make(map[string]*queryMeta)

// send results or not to the remote system
var sendResults bool

// hostname of the localhost
var host string

// config instance
var Params = Config{}

// Lock for query info
var queryInfoMapMutex = &sync.Mutex{}

// count of queries with packet size equal to capture size
var fullLengthQueryCount uint16
var abortedConnectionCount uint16
var accessDeniedCount uint16

/*
Read config from toml file and marshal to Config struct
*/
func ReadConfig() Config {
	ConfigFile := flag.String("config-file", "/etc/qan.toml", "Path to the configuration file")
	flag.Parse()
	viper.SetConfigType("toml")
	if len(os.Args) > 1 {
		ConfigPath := filepath.Dir(*ConfigFile)
		ConfigFullName := filepath.Base(*ConfigFile)
		Extension := filepath.Ext(ConfigFullName)
		ConfigName := ConfigFullName[0 : len(ConfigFullName)-len(Extension)]
		viper.AddConfigPath(ConfigPath)
		viper.SetConfigName(ConfigName)
	} else {
		viper.SetConfigName("qan")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/")
	}
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Unable to load config: %s", err)
		os.Exit(1)
	}
	if err := viper.Unmarshal(&Params); err != nil {
		fmt.Printf("Unable to read config: %s", err)
	}
	return Params
}

/*
This function opens the interface and sniffs packets over the port.
It extracts the source IP, source port, dest IP and dest port and determines it is request or response.
If the source port in the TCP header is same as the port that is being sniffed, it is considered as response otherwise, it is request
After extracting the info from the TCP header, processPayload is called to process the payload.
*/
func StartSniffer(ipaddrs []string) {
	var handle *pcap.Handle
	var fullLength bool = false
	handle, err := pcap.OpenLive(Params.Sniffer.ListenInterface, Params.Sniffer.CaptureLength, false, 0)
	if handle == nil || err != nil {
		msg := "unknown error"
		if err != nil {
			msg = err.Error()
		}
		log.Fatalf("ERROR: Failed to open device: %s", msg)
	}

	filter := fmt.Sprintf("tcp and port %d", uint16(Params.Sniffer.ListenPort))
	if len(ipaddrs) > 0 {
		ipFilter := "src host "
		// Ignore request originating from this server to remote server
		ipFilter += strings.Join(ipaddrs, " or src host ")
		filter = fmt.Sprintf("%s and not (dst port %d and (%s))", filter, uint16(Params.Sniffer.ListenPort), ipFilter)
	}

	if Params.Sniffer.IgnoreIPs != "" {
		ignoreIPs := strings.Split(Params.Sniffer.IgnoreIPs, ",")
		ignoreFilter := "host "
		ignoreFilter += strings.Join(ignoreIPs, " or host ")
		filter = fmt.Sprintf("%s and not (%s)", filter, ignoreFilter)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("ERROR: Failed to set port filter: %s", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		var src string
		var request bool = false
		SrcIP, DstIP := getIP(packet)
		if SrcIP != "" && DstIP != "" {
			SrcPort, DstPort, isRST := getTCPPort(packet)
			if SrcPort != 0 && DstPort != 0 {
				if Params.QanAgent.DebugMap[5] {
					log.Printf("From %s-%d to %s-%d\n", SrcIP, SrcPort, DstIP, DstPort)
				}
				if SrcPort == Params.Sniffer.ListenPort {
					src = fmt.Sprintf("%s-%d", DstIP, DstPort)
					request = false
				} else if DstPort == Params.Sniffer.ListenPort {
					src = fmt.Sprintf("%s-%d", SrcIP, SrcPort)
					request = true
				} else {
					log.Fatalf("ERROR: Got packet src = %d, dst = %d", SrcPort, DstPort)
				}
				if len(packet.Data()) == int(Params.Sniffer.CaptureLength) {
					fullLength = true
				} else {
					fullLength = false
				}
				processPayload(&src, request, packet, isRST, fullLength)
			}
		}
	}
}

/*
Returns the source IP and dest IP
*/
func getIP(packet gopacket.Packet) (string, string) {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ip, _ := ipv4Layer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String()
	}

	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ip, _ := ipv6Layer.(*layers.IPv6)
		return ip.SrcIP.String(), ip.DstIP.String()
	}
	return "", ""
}

/*
Returns the source port and dest port
*/
func getTCPPort(packet gopacket.Packet) (uint16, uint16, bool) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		SrcPort, _ := strconv.Atoi(fmt.Sprintf("%d", tcp.SrcPort))
		DstPort, _ := strconv.Atoi(fmt.Sprintf("%d", tcp.DstPort))
		return uint16(SrcPort), uint16(DstPort), tcp.RST
	}
	return 0, 0, false
}

/*
Returns the payload of the packet
*/
func getPayload(packet gopacket.Packet) []byte {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		return applicationLayer.Payload()
	}
	return nil
}

/*
Pass the payload to the protocol parser of the database.
*/
func processPayload(src *string, request bool, packet gopacket.Packet, isRST bool, fullLength bool) {
	payload := getPayload(packet)
	if len(payload) == 0 && !(isRST == true && request == false) {
		return
	}

	/*
	   If this is not a request, it means it is a response to an earlier request. If response comes, it means the query execution was
	   completed. Record the end time, calculate the total response time and pass the query to ProcessQuery to anonymize and further analytics
	*/
	if !request {
		sourceMapHandle, exists := MySQLProtocol.SourceMap[*src]
		if exists {
			// Discard entries with access denied requests
			if MySQLProtocol.IsErrPacket(&payload) {
				accessDeniedCount++
				delete(MySQLProtocol.SourceMap, sourceMapHandle.Src)
				if Params.QanAgent.DebugMap[9] {
					log.Printf("Error:%s\n", payload)
				}
				return
			}
			if isRST == false {
				if Params.QanAgent.DebugMap[6] {
					log.Printf("Source: %s\nResponse Packet: %s\n, Response Count: %d\n Response Length: %d\n", sourceMapHandle.Src, string(getPayload(packet)), sourceMapHandle.ResponseCount, len(payload))
				}
				sourceMapHandle.ResponseCount++
				sourceMapHandle.ResponseTime = float64(uint64(time.Since(sourceMapHandle.QueryEndTime).Nanoseconds())) / 1000000000
				// If you want to capture the response time from the first packet of the query till the first packet of response.
				// sourceMapHandle.totalResponseTime = float64(uint64(time.Since(sourceMapHandle.QueryStartTime).Nanoseconds())) / 1000000000
				if sourceMapHandle.FullLength == true {
					fullLengthQueryCount++
					if Params.QanAgent.DebugMap[3] {
						log.Printf("Full Length Query\n*************\nSource: %s\nTime: %f\nUser: %s\nDB: %s\nQuery: %s\n------------------------------\n", sourceMapHandle.Src, sourceMapHandle.ResponseTime, sourceMapHandle.User, sourceMapHandle.Db, sourceMapHandle.QueryText)
					}
				}
				if sourceMapHandle.QueryText != "" && sourceMapHandle.PreparedStatement == false {
					if sourceMapHandle.FullLength == false {
						if Params.QanAgent.DebugMap[2] {
							log.Printf("Source: %s\nTime: %f\nUser: %s\nDB: %s\nQuery: %s\n------------------------------\n", sourceMapHandle.Src, sourceMapHandle.ResponseTime, sourceMapHandle.User, sourceMapHandle.Db, sourceMapHandle.QueryText)
							if Params.QanAgent.DebugMap[4] {
								log.Printf("Length of Query Hashmap: %d\n******************************\n", len(MySQLProtocol.SourceMap))
							}
						}
						// Asynchronous query processing
						go processQuery(*sourceMapHandle)
					}
					// Reset the hashmap for the source to handle the next requests from the same connection
					sourceMapHandle.QueryText = ""
					sourceMapHandle.RequestLength = 0
					sourceMapHandle.NewConnection = false
					if len(MySQLProtocol.SourceMap) > Params.QanAgent.MaxDBConnections {
						if Params.QanAgent.DebugMap[7] {
							log.Printf("Length of Query Hashmap before cleanup: %d\n******************************\n", len(MySQLProtocol.SourceMap))
							log.Printf("Query Hashmap:\n******************************\n")
						}
						for key, _ := range MySQLProtocol.SourceMap {
							if Params.QanAgent.DebugMap[8] {
								log.Printf("%s:%v\n", key, MySQLProtocol.SourceMap[key])
							}
							if MySQLProtocol.SourceMap[key].QueryText == "" || uint64((uint64(time.Since(MySQLProtocol.SourceMap[key].QueryEndTime).Nanoseconds()))/1000000000) > 3600 {
								if Params.QanAgent.DebugMap[7] {
									log.Printf("Length of Query Hashmap after deleting queries > 3600 secs: %d\n******************************\n", len(MySQLProtocol.SourceMap))
									log.Printf("SRC: %s, DURATION: %d, Sync: %t\n", key, uint64(time.Since(MySQLProtocol.SourceMap[key].QueryStartTime).Seconds()), MySQLProtocol.SourceMap[key].NewConnection)
									log.Printf("SRC: %s, Query: %s, Sync: %t\n", key, MySQLProtocol.SourceMap[key].QueryText, MySQLProtocol.SourceMap[key].NewConnection)
								}
								delete(MySQLProtocol.SourceMap, key)
							}
						}
						if Params.QanAgent.DebugMap[7] {
							log.Printf("Length of Query Hashmap after cleanup: %d\n******************************\n", len(MySQLProtocol.SourceMap))
						}
						// If entries in MySQLProtocol.SourceMap get deleted, the user and db information is lost. You can optionally uncomment these lines and repopulate the user and db information from the processlist.
						/*
						if Params.LocalDB.Enabled == 1 {
							MySQLProtocol.GetProcesslist()
						}
						*/
					}
				}
			} else {
				delete(MySQLProtocol.SourceMap, sourceMapHandle.Src)
				if Params.QanAgent.DebugMap[7] {
					log.Printf("Length of Query Hashmap after delete RST: %d\n******************************\n", len(MySQLProtocol.SourceMap))
				}
				abortedConnectionCount++
			}
		}
		return
	}

	// If it is a request, call ParseProtocol function to extract the query from the packet
	MySQLProtocol.ParseProtocol(src, &payload, fullLength)
}

func processQuery(sourceMapHandle MySQLProtocol.Source) (err error) {
	defer func() {
		// recover from panic if one occured. Set err to nil otherwise.
		if recover() != nil {
			log.Printf("Failed while processing query.\nDetails: %v", sourceMapHandle)
			err = errors.New("Unknown Exception")
		}
	}()
	fp, checksum := MySQLProtocol.AnonymizeQuery(sourceMapHandle.QueryText)
	procUserMapHandle, ok := MySQLProtocol.ProcUserMap[sourceMapHandle.Src]
	if ok {
		sourceMapHandle.User = procUserMapHandle.User
		sourceMapHandle.Db = procUserMapHandle.Db
	} else {
		if (len(sourceMapHandle.User) == 0) || (len(sourceMapHandle.User) > 16) {
			sourceMapHandle.User = "unknown"
		}
		if (len(sourceMapHandle.Db) == 0) || (len(sourceMapHandle.Db) > 64) {
			sourceMapHandle.Db = "unknown"
		}
	}
	src := strings.Split(sourceMapHandle.Src, "-")[0]
	queryInfoMapMutex.Lock()
	queryInfoMapHandle, ok := queryInfoMap[checksum]
	if !ok {
		queryInfoMapHandle = &queryInfo{checksum: checksum, src: src, user: sourceMapHandle.User, db: sourceMapHandle.Db, fingerprint: fp, count: 1, sample: sourceMapHandle.QueryText, queryTime: sourceMapHandle.ResponseTime, minTime: sourceMapHandle.ResponseTime, maxTime: sourceMapHandle.ResponseTime, bytesIn: sourceMapHandle.RequestLength}
		queryInfoMap[checksum] = queryInfoMapHandle
	} else {
		queryInfoMapHandle.queryTime += sourceMapHandle.ResponseTime
		queryInfoMapHandle.count++
		queryInfoMapHandle.bytesIn += sourceMapHandle.RequestLength
		if queryInfoMapHandle.maxTime < sourceMapHandle.ResponseTime {
			queryInfoMapHandle.maxTime = sourceMapHandle.ResponseTime
			queryInfoMapHandle.sample = sourceMapHandle.QueryText
		}
		if queryInfoMapHandle.minTime > sourceMapHandle.ResponseTime {
			queryInfoMapHandle.minTime = sourceMapHandle.ResponseTime
		}
	}
	if Params.QanAgent.DebugMap[1] {
		log.Printf("Source: %s\nChecksum: %s\nUser: %s\nDB: %s\nFingerprint: %s\nCount: %d\nSample: %s\nqueryTime: %g\nminTime: %g\nmaxTime: %g\nbytesIn: %d\n------------------------------------\n", queryInfoMapHandle.src, queryInfoMapHandle.checksum, queryInfoMapHandle.user, queryInfoMapHandle.db, queryInfoMapHandle.fingerprint, queryInfoMapHandle.count, queryInfoMapHandle.sample, queryInfoMapHandle.queryTime, queryInfoMapHandle.minTime, queryInfoMapHandle.maxTime, queryInfoMapHandle.bytesIn)
	}
	queryInfoMapMutex.Unlock()
	return
}

func sendResultsToDB(host string) (err error) {
	defer func() {
		// recover from panic if one occured. Set err to nil otherwise.
		if recover() != nil {
			log.Printf("Failed while sending results to remote system\n")
			err = errors.New("Unknown Exception")
		}
	}()
	if Params.RemoteDB.Enabled != 1 {
		return
	}
	var db *sql.DB
	var tlsmode string = "false"
	var selfsigned bool = false
	var conn string
	var queryInfoMapLength int

	switch Params.RemoteDB.SSLEnabled {
	case 0:
		tlsmode = "false"
	case 1:
		tlsmode = "skip-verify"
	case 2:
		tlsmode = "custom"
		selfsigned = true
	case 3:
		tlsmode = "custom"
		selfsigned = false
	default:
		tlsmode = "skip-verify"
	}

	// switch to skip-verify if any of Ca_cert, Client_cert and Client_key are not specified
	if tlsmode == "custom" && Params.RemoteDB.Ca_cert != "" && Params.RemoteDB.Client_cert != "" && Params.RemoteDB.Client_key != "" {
		tlsmode = "custom"
	} else if tlsmode == "custom" {
		tlsmode = "skip-verify"
	}

	if tlsmode == "custom" {
		rootCertPool := x509.NewCertPool()
		pem, err := ioutil.ReadFile(Params.RemoteDB.Ca_cert)
		if err != nil {
			log.Fatalf("Unable to open the CA certs - %s", err)
		}
		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			log.Fatal("Failed to append PEM.")
		}
		clientCert := make([]tls.Certificate, 0, 1)
		certs, err := tls.LoadX509KeyPair(Params.RemoteDB.Client_cert, Params.RemoteDB.Client_key)
		if err != nil {
			log.Fatalf("Unable to open the Client certs and Client Key - %s", err)
		}
		clientCert = append(clientCert, certs)
		mysql.RegisterTLSConfig("custom", &tls.Config{
			RootCAs:            rootCertPool,
			Certificates:       clientCert,
			InsecureSkipVerify: selfsigned,
		})
		conn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=custom&autocommit=true&charset=utf8mb4", Params.RemoteDB.Username, Params.RemoteDB.Password, Params.RemoteDB.Hostname, Params.RemoteDB.Port, Params.RemoteDB.DBName)
	} else {
		conn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%s&autocommit=true&charset=utf8mb4", Params.RemoteDB.Username, Params.RemoteDB.Password, Params.RemoteDB.Hostname, Params.RemoteDB.Port, Params.RemoteDB.DBName, tlsmode)
	}

	db, err = sql.Open("mysql", conn)
	if err != nil {
		log.Fatalf("Unable to open the DB Connection - %s", err.Error())
	}
	// sql.DB should be long lived "defer" closes it once this function ends
	defer db.Close()

	// Test the connection to the database
	err = db.Ping()
	if err != nil {
		log.Fatalf("ERROR: Unable to ping database - %s", err)
	}

	queryInfoSQL := `INSERT INTO query_info (hostname, checksum, fingerprint, sample, firstseen, mintime, mintimeat, maxtime, maxtimeat)
                VALUES (?, ?, ?, ?, UTC_TIMESTAMP(), ?, UTC_TIMESTAMP(), ?, UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE
                sample = CASE WHEN maxtime >= ? THEN sample ELSE ? END,
                maxtimeat = CASE WHEN maxtime >= ? THEN maxtimeat ELSE UTC_TIMESTAMP() END,
                mintimeat = CASE WHEN mintime <= ? THEN mintimeat ELSE UTC_TIMESTAMP() END,
                maxtime = CASE WHEN maxtime >= ? THEN maxtime ELSE ? END,
                mintime = CASE WHEN mintime <= ? THEN mintime ELSE ? END`
	queryInfoSQLHandle, err := db.Prepare(queryInfoSQL)

	if err != nil {
		log.Fatalf("ERROR: Unable to prepare SQL statement")
	}

	for {
		// Make a copy to avoid data race condition. TODO - implement concurrent maps or use channels
		queryInfoMapMutex.Lock()
		for checksum, data := range queryInfoMap {
			queryInfoCopyMap[checksum] = data
			delete(queryInfoMap, checksum)
		}
		queryInfoMapMutex.Unlock()
		queryInfoMapLength = len(queryInfoCopyMap)

		if sendResults == true && queryInfoMapLength > 0 {
			queryHistoryCols := make([]string, 0, queryInfoMapLength)
			vals := make([]interface{}, 0, queryInfoMapLength*6)
			utcnow := time.Now().UTC().Format("2006-01-02 15:04:05")

			for checksum, data := range queryInfoCopyMap {
				var upsert bool
				if Params.RemoteDB.IncludeSample == 0 {
					data.sample = ""
				}

				// Uncomment these lines if pseudo GTID has to be ignored
				/*
				// Ignore pseudo GTID
				if strings.Contains(data.sample, "drop view if exists `_pseudo_gtid_`") {
					delete(queryMetaMap, data.checksum)
					delete(queryInfoCopyMap, checksum)
					continue
				}
				*/

				queryHistoryCols = append(queryHistoryCols, "(?,?,?,?,?,?,?,?,?)")
				vals = append(vals, host, data.checksum, data.src, data.user, data.db, utcnow, data.count, data.queryTime, data.bytesIn)

				delete(queryInfoCopyMap, checksum)

				queryMetaMapHandle, exists := queryMetaMap[data.checksum]
				if !exists {
					queryMetaMapHandle = &queryMeta{checksum: checksum, minTime: data.minTime, maxTime: data.maxTime}
					queryMetaMap[checksum] = queryMetaMapHandle
					_, err = queryInfoSQLHandle.Exec(host, data.checksum, data.fingerprint, data.sample, data.minTime, data.maxTime, data.maxTime, data.sample, data.maxTime, data.minTime, data.maxTime, data.maxTime, data.minTime, data.minTime)
					if err != nil {
						log.Printf("ERROR: Unable to insert into query_info table: %s", err)
						log.Printf("SQL (query_info): %s\nChecksum: %s\nFingerprint: %s\nSample: %s\nMaxTime: %f\nMinTime: %f\n------------------------------", queryInfoSQL, data.checksum, data.fingerprint, data.sample, data.maxTime, data.minTime)
					}
				} else {
					if data.maxTime > queryMetaMapHandle.maxTime {
						queryMetaMapHandle.maxTime = data.maxTime
						upsert = true
					}

					if data.minTime < queryMetaMapHandle.minTime {
						queryMetaMapHandle.minTime = data.minTime
						upsert = true
					}

					if upsert == true {
						_, err = queryInfoSQLHandle.Exec(host, data.checksum, data.fingerprint, data.sample, data.minTime, data.maxTime, data.maxTime, data.sample, data.maxTime, data.minTime, data.maxTime, data.maxTime, data.minTime, data.minTime)
						if err != nil {
							log.Printf("ERROR: Unable to upsert into query_info table: %s", err)
						}
						upsert = false
					}
				}
			}
			// Doing batch insert
			queryHistorySQL := fmt.Sprintf("INSERT INTO query_history (hostname, checksum, src, user, db, ts, count, querytime, bytes) VALUES %s", strings.Join(queryHistoryCols, ","))
			_, err := db.Exec(queryHistorySQL, vals...)
			if err != nil {
				log.Printf("ERROR: Unable to insert into query_history table %s %s: %s", queryHistorySQL, vals, err)
			}
			sendResults = false
		} else {
			time.Sleep(time.Second * time.Duration(Params.QanAgent.ReportInterval))
			sendResults = true
			if Params.QanAgent.DebugMap[4] {
				log.Printf("Length of Query Info Hashmap: %d\n******************************\n", queryInfoMapLength)
			}
		}
	}
}

/*
This function logs the number of queries with packet size equal to or more than the capture size, aborted connection count (wait timeout, connection reset etc)
*/
func logStats() {
	for {
		if fullLengthQueryCount > 65535 {
			fullLengthQueryCount = 1
		}
		if abortedConnectionCount > 65535 {
			abortedConnectionCount = 1
		}
		if accessDeniedCount > 65535 {
			accessDeniedCount = 1
		}
		log.Printf("%s\nNumber of queries more than Capture Length: %d\nNumber of aborted connections: %d\nNumber of access denied requests: %d\n", time.Now().Format("2006-01-02 15:04:05"), fullLengthQueryCount, abortedConnectionCount, accessDeniedCount)
		time.Sleep(time.Second * time.Duration(Params.Sniffer.ReportStatsInterval))
	}
}

func main() {
	var ip string
	var ipaddrs []string

	Params = ReadConfig()
	if Params.QanAgent.MaxDBConnections == 0 {
		Params.QanAgent.MaxDBConnections = 1024
	}
	levels := strings.Split(Params.QanAgent.DebugLevels, ",")
	// Create hashmap of debug levels
	Params.QanAgent.DebugMap = make(map[uint8]bool)
	for _, element := range levels {
		level, _ := strconv.Atoi(element)
		Params.QanAgent.DebugMap[uint8(level)] = true
	}

	LogFile, err := os.OpenFile(Params.QanAgent.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("Error opening log file, using STDOUT: %v", err)
	} else {
		log.SetOutput(LogFile)
	}
	defer LogFile.Close()

	log.SetPrefix("")
	log.SetFlags(0)
	log.Printf("%s\nStarting Sniffer\n", time.Now().Format("2006-01-02 15:04:05"))

	host, err := os.Hostname()
	if err != nil {
		log.Fatalf("Unable to identify the hostname: %s", err)
	}

	ifaces, _ := net.Interfaces()
	// handle err
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				ip = fmt.Sprintf("%s", v.IP)
				if ip != "127.0.0.1" && ip != "::1" {
					ipaddrs = append(ipaddrs, ip)
				}
			case *net.IPAddr:
				ip = fmt.Sprintf("%s", v.IP)
				ipaddrs = append(ipaddrs, ip)
			}
		}
	}

	// Pass the config params to the Protocol parser file
	MySQLProtocol.LocalDBConfigParams = MySQLProtocol.LocalDBConfig(Params.LocalDB)
	MySQLProtocol.QanAgentConfigParams = MySQLProtocol.QanAgentConfig(Params.QanAgent)

	// Send the results to the remote server
	go sendResultsToDB(host)

	// Print the number of queries with packet size equal to or more than the capture size and alsos aborted connections
	if Params.Sniffer.ReportStatsInterval > 0 {
		go logStats()
	}
	if Params.LocalDB.Enabled == 1 {
		MySQLProtocol.GetProcesslist()
	}
	StartSniffer(ipaddrs)
}
