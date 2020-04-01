package MySQLProtocol

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/percona/go-mysql/query"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
)

/*
MySQL packet type constants
*/
const (
	COM_SLEEP                    = 0x00
	COM_QUIT                     = 0x01
	COM_INIT_DB                  = 0x02
	COM_QUERY                    = 0x03
	COM_FIELD_LIST               = 0x04
	COM_CREATE_DB                = 0x05
	COM_DROP_DB                  = 0x06
	COM_REFRESH                  = 0x07
	COM_SHUTDOWN                 = 0x08
	COM_STATISTICS               = 0x09
	COM_PROCESS_INFO             = 0x0a
	COM_CONNECT                  = 0x0b
	COM_PROCESS_KILL             = 0x0c
	COM_DEBUG                    = 0x0d
	COM_PING                     = 0x0e
	COM_TIME                     = 0x0f
	COM_DELAYED_INSERT           = 0x10
	COM_CHANGE_USER              = 0x11
	COM_BINLOG_DUMP              = 0x12
	COM_TABLE_DUMP               = 0x13
	COM_CONNECT_OUT              = 0x14
	COM_REGISTER_SLAVE           = 0x15
	COM_STMT_PREPARE             = 0x16
	COM_STMT_EXECUTE             = 0x17
	COM_STMT_SEND_LONG_DATA      = 0x18
	COM_STMT_CLOSE               = 0x19
	COM_STMT_RESET               = 0x1a
	COM_SET_OPTION               = 0x1b
	COM_STMT_FETCH               = 0x1c
	iOK                     byte = 0x00
	iEOF                    byte = 0xfe
	iERR                    byte = 0xff
)

// Config struct to hold config related to connecting to local db
type LocalDBConfig struct {
	LocalUsername string
	LocalPassword string
	LocalSocket   string
	Enabled       uint8
}

// Config struct to hold qan agent config section
type QanAgentConfig struct {
	ReportInterval   uint32
	MaxRequestLength uint32
	MaxDBConnections int
	DebugLevels      string
	LogFile          string
	DebugMap         map[uint8]bool
}

// Struct for packet related information
type Source struct {
	Src               string
	QueryStartTime    time.Time
	QueryEndTime      time.Time
	RequestCount      uint16
	ResponseCount     uint16
	RequestLength     uint32
	QueryText         string
	ResponseTime      float64
	User              string
	Db                string
	NewConnection     bool
	PreparedStatement bool
	FullLength        bool
}

// Struct for storing the processlist
type ProcUser struct {
	Src  string
	User string
	Db   string
}

// Hashmap for processlist
var ProcUserMap map[string]*ProcUser = make(map[string]*ProcUser)

// Hashmap for the packet information
var SourceMap map[string]*Source = make(map[string]*Source)

// hostname of the localhost
var host string

// LocalDBConfig instance
var LocalDBConfigParams = LocalDBConfig{}

// QanAgentConfig instance
var QanAgentConfigParams = QanAgentConfig{}

var parseUserRegex = regexp.MustCompile("([0-9a-z]+)(?P<filler>00{23})(?P<user>[0-9a-z]+)00([0-9a-z]{42})(?P<db>[1-9a-z]+0{0,1}[1-9a-z]*0{0,1})00([0-9a-z]+)")

/*
This function extracts queries from the packet. If the packet is a continuation of an earlier request, it will be added to the request.
TODO: Need to add support for compressed packets and SSL connections.
*/
func ParseProtocol(src *string, payload *[]byte, fullLength bool) (err error) {
	var MySQLPacketType byte = 0xff
	var MySQLPacketData []byte
	defer func() {
		// recover from panic if one occured. Set err to nil otherwise.
		if recover() != nil {
			log.Printf("Failed while parsing protocol. Details: %v", src)
			err = errors.New("Unknown Exception")
		}
	}()

	MySQLPacketType, MySQLPacketData = parsePacket(payload)
	packetLength := len(MySQLPacketData)

	if QanAgentConfigParams.DebugMap[5] {
		log.Printf("Source: %s\n, MySQLPacket Length: %d\nMySQLPacketType: %d\nMySQLPacketData: %s\n", *src, packetLength, MySQLPacketType, MySQLPacketData)
	}

	if MySQLPacketType == iERR {
		return
	}

	sourceMapHandle, exists := SourceMap[*src]
	if !exists {
		sourceMapHandle = &Source{Src: *src, RequestCount: 0, ResponseCount: 0, QueryStartTime: time.Now(), QueryEndTime: time.Now(), NewConnection: true}
		SourceMap[*src] = sourceMapHandle
		if QanAgentConfigParams.DebugMap[5] {
			log.Printf("New connection from %s\n", sourceMapHandle.Src)
		}
	} else {
		sourceMapHandle.QueryStartTime = time.Now()
		sourceMapHandle.QueryEndTime = time.Now()
	}

	if sourceMapHandle.FullLength == false {
		sourceMapHandle.FullLength = fullLength
	}

	// COM_QUIT Packet
	if MySQLPacketType == COM_QUIT {
		delete(SourceMap, sourceMapHandle.Src)
		if QanAgentConfigParams.DebugMap[4] {
			log.Printf("Deleting on COM_QUIT %s\nLength of Query Hashmap: %d\n", sourceMapHandle.Src, len(SourceMap))
		}
		return
	}

	if sourceMapHandle.NewConnection == true {
		sourceMapHandle.User, sourceMapHandle.Db = parseUserInfo(src, *payload)
		sourceMapHandle.NewConnection = false
	}

	if MySQLPacketType == COM_INIT_DB {
		sourceMapHandle.Db = string(MySQLPacketData)
		sourceMapHandle.RequestCount++
		return
	}

	if MySQLPacketType == COM_STMT_PREPARE {
		sourceMapHandle.QueryText = string(MySQLPacketData)
		sourceMapHandle.RequestCount++
		sourceMapHandle.PreparedStatement = true
		return
	}

	if MySQLPacketType == COM_STMT_EXECUTE {
		if sourceMapHandle.QueryText != "" {
			sourceMapHandle.RequestCount++
			sourceMapHandle.QueryStartTime = time.Now()
			sourceMapHandle.PreparedStatement = false
		}
		return
	}

	if MySQLPacketType == COM_QUERY {
		sourceMapHandle.RequestLength += uint32(packetLength)
		// Do not process requests more than 512K, probably huge insert
		if sourceMapHandle.RequestLength < QanAgentConfigParams.MaxRequestLength {
			queryString := string(MySQLPacketData)
			sourceMapHandle.RequestCount++
			if sourceMapHandle.RequestCount <= 3 && strings.Contains(queryString, "select @@version_comment limit 1") {
				sourceMapHandle.QueryText = ""
			} else {
				// Sometimes the set autocommit = 0 and commit is sent along with the request.
				if !(strings.EqualFold(queryString, "commit") || strings.EqualFold(queryString, "rollback") || strings.EqualFold(queryString, "set autocommit = 0") || strings.EqualFold(queryString, "set autocommit = 1")) && sourceMapHandle.QueryText != queryString {
					sourceMapHandle.QueryText = queryString
				}
			}
		}
		return
	}

	// probably part of earlier request
	if exists {
		if sourceMapHandle.QueryText != "" {
			queryString := string(MySQLPacketData)
			sourceMapHandle.RequestCount++
			sourceMapHandle.QueryText += queryString
		}
		if sourceMapHandle.RequestLength >= QanAgentConfigParams.MaxRequestLength {
			if QanAgentConfigParams.DebugMap[4] {
				log.Printf("Truncating huge insert: %s", sourceMapHandle.QueryText)
			}
			sourceMapHandle.QueryText = ""
		}
	}

	// Uncomment these lines to clean up the orphan packets. Cleaning up will wipe off the user and db information also.
	/*
	if (len(SourceMap)>1024) {
	    for key, _ := range SourceMap {
	        if SourceMap[key].ResponseCount > 3 && SourceMap[key].QueryText == "" {
	            delete(SourceMap, key)
	        }
	    }
	}
	*/
	return
}

/*
This function returns the username and the database name if it is a connection request packet
TODO: This only support mysql_native_password authentication mechanism, need to add support for sha_256 plugin and others
*/

func parseUserInfo(src *string, payload []byte) (string, string) {
	var user string
	var db string
	payloadLength := len(payload)
	// max username is 16 chars (32 chars in version >= 5.7.8) and max database name is 64 chars
	if payloadLength >= 59 && payloadLength <= 285 {

		var userOffset int
		var dbOffset int

		/*
		   First 3 bytes    - Packet Length
		   Next byte        - Packet Number
		   Next 2 bytes     - Client Capabilities
		   Next 2 bytes     - Extended Client Capabilities
		   Next 5 bytes     - Max packet size, charset
		   Next 23 bytes    - Filled with 00
		   (so we can ignore first 36 bytes)
		   (..)00           - Null-terminated user name
		   ([0-9][a-f]){22} - Hashed Password
		   (..)00           - Null-terminated database name
		*/

		// get user information
		for i := 1; i < payloadLength-36; i++ {
			if payload[36+i] == '\x00' {
				userOffset = i
				break
			}
		}

		if string(payload[36:36+userOffset]) != "" {
			user = string(payload[36 : 36+userOffset])
		}

		// get db information
		for j := 36 + userOffset + 22; j < len(payload); j++ {
			if payload[j] == '\x00' {
				dbOffset = j
				break
			}
		}
		if 36+userOffset+22 < dbOffset && dbOffset < payloadLength && string(payload[36+userOffset+22:dbOffset]) != "" {
			db = string(payload[36+userOffset+22 : dbOffset])
			if strings.Contains(db, "mysql_native_password") {
				db = ""
			}
		}

        	// Doing it in regex way
		/*
		matches := parseUserRegex.FindStringSubmatch(string(payload))
		names := parseUserRegex.SubexpNames()
		for i, match := range matches {
			if i != 0 {
				if names[i] == "user" {
					t, _ := hex.DecodeString(match)
					user = string(t)
				}
				if names[i] == "db" {
					g, _ := hex.DecodeString(match)
					db = string(g)
				}
			}
		}
		*/

		if QanAgentConfigParams.DebugMap[4] {
			log.Printf("New Connection\nUser:%s\nDB:%s\n", user, db)
		}
	}
	return user, db
}

/*
This function returns the packet type which is the 5th byte of the packet and the packet data
*/

func parsePacket(buf *[]byte) (byte, []byte) {
	dataLength := len(*buf)
	if dataLength <= 5 {
		if dataLength == 5 && (*buf)[4] == COM_QUIT {
			// COM_QUIT Packet
			return COM_QUIT, nil
		}
		return iERR, nil
	}
	MySQLPacketType := (*buf)[4]
	MySQLPacketData := (*buf)[5:]
	return MySQLPacketType, MySQLPacketData
}

/*
This function is same as parsePacket function except this is only for checking whether there is error in response based on
the packet type which is the 5th byte of the packet.
*/

func IsErrPacket(payload *[]byte) bool {
	if len(*payload) >= 7 && (*payload)[4] == iERR {
		// ERROR 1044 (42000): Access denied for user 'xxxx'@'xxxx' to database 'xxxx'
		// ERROR 1045 (28000): Access denied for user 'xxxx'@'xxxx' (using password: YES)
		// ERROR 1049 (42000): Unknown database 'xxxx'
		if (*payload)[6] == 0x04 && ((*payload)[5] == 0x14 || (*payload)[5] == 0x15 || (*payload)[5] == 0x19) {
			return true
		}
	}
	return false
}

/*
This function anonymizes the data from a query by replacing it with ? and calculates the checksum of the query using Percona go-query.
*/
func AnonymizeQuery(queryText string) (string, string) {
	fp := query.Fingerprint(queryText)
	checksum := query.Id(fp)
	return fp, checksum
}

func GetProcesslist() {
	var db *sql.DB
	var err error
	var src string
	var user string
	var dbname string

	// clear entries
	for key, _ := range ProcUserMap {
		delete(ProcUserMap, key)
	}

	localSQLHandle := fmt.Sprintf("%s:%s@unix(%s)/information_schema", LocalDBConfigParams.LocalUsername, LocalDBConfigParams.LocalPassword, LocalDBConfigParams.LocalSocket)
	db, err = sql.Open("mysql", localSQLHandle)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Printf("ERROR: Unable to connect to local database to get processlist: %s", err)
		return
	}

	rows, err := db.Query("SELECT HOST, USER, DB FROM INFORMATION_SCHEMA.PROCESSLIST WHERE HOST!=''")
	for rows.Next() {
		hostname := ""
		port := ""
		rows.Scan(&src, &user, &dbname)
		if strings.Contains(src, ":") {
			// src := "example-app1234.linkedin.com:55380"
			// src := "2405:2300:ff02:6005:7338:6962:863b:595a:55380"
			// src := "::1:55380"
			src_split := strings.Split(src, ":")
			hostname = strings.Join(src_split[:len(src_split)-1], ":")
			port = src_split[len(src_split)-1]
		}
		ips, err := net.LookupHost(hostname)
		if err == nil && len(ips) > 0 && len(port) > 0 {
			for _, ip := range ips {
				src = fmt.Sprintf("%s@%s", ip, port)
				ProcUserMapHandle, exists := ProcUserMap[src]
				if !exists {
					ProcUserMapHandle = &ProcUser{Src: src, User: user, Db: dbname}
					ProcUserMap[src] = ProcUserMapHandle
				}
			}
		} else if len(port) > 0 {
			src = fmt.Sprintf("%s@%s", hostname, port)
			ProcUserMapHandle, exists := ProcUserMap[src]
			if !exists {
				ProcUserMapHandle = &ProcUser{Src: src, User: user, Db: dbname}
				ProcUserMap[src] = ProcUserMapHandle
			}
		}
	}
	if QanAgentConfigParams.DebugMap[10] {
		for key, value := range ProcUserMap {
			log.Printf("Processlist:%s, %s\n", key, *value)
		}
	}
}
