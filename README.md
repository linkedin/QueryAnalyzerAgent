# Query Analyzer Agent - Capture and analyze the queries without overhead.

Query Analyzer Agent runs on the database server. It captures all the queries by sniffing the network port, aggregates the queries and sends results to a remote server for further analysis. Refer to [LinkedIn's Engineering Blog](https://engineering.linkedin.com/blog/2017/09/query-analyzer--a-tool-for-analyzing-mysql-queries-without-overh) for more details.

## Getting Started
### Prerequisites
Query Analyzer Agent is written in Go, so before you get started you should [install and setup Go](https://golang.org/doc/install). You can also follow the steps here to install and setup Go.
```
$ wget https://dl.google.com/go/go1.14.linux-amd64.tar.gz
$ sudo tar -C /usr/local -xzf go1.14.linux-amd64.tar.gz
$ mkdir ~/projects
$ export PATH=$PATH:/usr/local/go/bin
$ export GOPATH=~/projects
$ export GOBIN=~/projects/bin
```

Query Analyzer Agent requires the following external libraries
- pcap.h (provided by libpcap-dev package), gcc or build-essential for building this package
    - RHEL/CentOs/Fedora:
      ```
      $ sudo yum install gcc libpcap libpcap-devel
      ```
    - Debian/Ubuntu:
      ```
      $ sudo apt-get install build-essential libpcap-dev
      ```
- [Go-MySQL-Driver](https://github.com/go-sql-driver/mysql)
  ```
  $ go get github.com/go-sql-driver/mysql
  ```

### Third Party Libraries
Go build system automatically downloads the following third party tools from the respective github repository during the compilation of this project.
```
GoPacket
https://github.com/google/gopacket
Copyright (c) 2012 Google, Inc. All rights reserved.
Copyright (c) 2009-2011 Andreas Krennmair. All rights reserved.
License: BSD 3-Clause "New" or "Revised" License

Percona Go packages for MySQL
https://github.com/percona/go-mysql
Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
License: BSD 3-Clause "New" or "Revised" License

Viper
https://github.com/spf13/viper
Copyright (c) 2014 Steve Francia
License: MIT
```

### Setting up remote database
Query Analyzer Agent either prints the aggregated queries to a local log file or sends to a remote database which can store queries collected from all the agents. We have chosen MySQL as the remote database.

Execute the following SQL statements on the remote database server.
```
mysql> CREATE DATABASE IF NOT EXISTS `query_analyzer`;

mysql> CREATE TABLE IF NOT EXISTS `query_analyzer`.`query_info` (
  `hostname` varchar(64) NOT NULL DEFAULT '',
  `checksum` char(16) NOT NULL DEFAULT '',
  `fingerprint` longtext NOT NULL,
  `sample` longtext CHARACTER SET utf8mb4,
  `firstseen` datetime NOT NULL,
  `mintime` float NOT NULL DEFAULT '0',
  `mintimeat` datetime NOT NULL,
  `maxtime` float NOT NULL DEFAULT '0',
  `maxtimeat` datetime NOT NULL,
  `is_reviewed` enum('0','1','2') NOT NULL DEFAULT '0',
  `reviewed_by` varchar(20) DEFAULT NULL,
  `reviewed_on` datetime DEFAULT NULL,
  `comments` mediumtext,
  PRIMARY KEY (`hostname`,`checksum`),
  KEY `checksum` (`checksum`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=4;

mysql> CREATE TABLE IF NOT EXISTS `query_analyzer`.`query_history` (
  `hostname` varchar(64) NOT NULL DEFAULT '',
  `checksum` char(16) NOT NULL DEFAULT '',
  `src` varchar(39) NOT NULL DEFAULT '',
  `user` varchar(16) DEFAULT NULL,
  `db` varchar(64) NOT NULL DEFAULT '',
  `ts` datetime NOT NULL,
  `count` int unsigned NOT NULL DEFAULT '1',
  `querytime` float NOT NULL DEFAULT '0',
  `bytes` int unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`hostname`,`checksum`,`ts`),
  KEY `checksum` (`checksum`),
  KEY `user` (`user`),
  KEY `covering` (`hostname`,`ts`,`querytime`,`count`,`bytes`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8
/*!50100 PARTITION BY RANGE (TO_DAYS(ts))
(PARTITION p202002 VALUES LESS THAN (TO_DAYS('2020-03-01')) ENGINE = InnoDB,
 PARTITION p202003 VALUES LESS THAN (TO_DAYS('2020-04-01')) ENGINE = InnoDB,
 PARTITION p202004 VALUES LESS THAN (TO_DAYS('2020-05-01')) ENGINE = InnoDB,
 PARTITION p202005 VALUES LESS THAN (TO_DAYS('2020-06-01')) ENGINE = InnoDB,
 PARTITION p202006 VALUES LESS THAN (TO_DAYS('2020-07-01')) ENGINE = InnoDB,
 PARTITION p202007 VALUES LESS THAN (TO_DAYS('2020-08-01')) ENGINE = InnoDB,
 PARTITION pMAX VALUES LESS THAN (MAXVALUE) ENGINE = InnoDB) */;
/* You can use different partition scheme based on your retention */

mysql> CREATE USER /*!50706 IF NOT EXISTS*/ 'qan_rw'@'qan_agent_ip' IDENTIFIED BY 'Complex_P@ssw0rd';

mysql> GRANT SELECT, INSERT, UPDATE ON `query_analyzer`.* TO 'qan_rw'@'qan_agent_ip';
```
The above SQLs can be found in remote_database/remote_schema.sql and remote_database/users.sql files.

## Build and Install
```
$ git clone https://github.com/linkedin/QueryAnalyzerAgent
$ cd QueryAnalyzerAgent
$ go get
$ go build -o $GOBIN/QueryAnalyzerAgent
```

## Configuration
QueryAnalyzerAgent config is in TOML format which is organized into several subheadings. For the basic use, you need to specify the Ethernet Interface, Port and connection details of remote database endpoint in the config file - qan.toml

Once the remote database is setup, update qan.toml
```
[remoteDB]
Enabled = 1

# remote database hostname to send results to
Hostname = "remote_database_hostname"

# remote database port to send results to
Port = 3306

# remote database username to send results to
Username = "qan_rw"

# remote database password to send results to
Password = "Complex_P@ssw0rd"

# remote database name to send results to
DBName = "query_analyzer"
```

If user and db details of connection are needed, create a user to connect to the local database and update the localDB section. Create user SQL can be found at local_database/users.sql


## Running Query Analyzer Agent
```
Since the agent sniffs the network interface, it should have net_raw capability.
$ sudo setcap cap_net_raw+ep $GOBIN/QueryAnalyzerAgent
$ $GOBIN/QueryAnalyzerAgent --config-file qan.toml (or complete path to qan.toml)

If you do not set the net_raw capability, you can run the agent as a root user.
$ sudo $GOBIN/QueryAnalyzerAgent --config-file qan.toml (or complete path to qan.toml)
```

## Query Analytics
Once you understand the schema, you can write queries and build fancy UI to extract the information you want.
Examples:

* Top 5 queries which have the maximum total run time during a specific interval. If a query takes 1 second and executes 1000 times, the total run time is 1000 seconds.
  ```
  SELECT 
      SUM(count),
      SUM(querytime) 
  INTO 
      @count, @qt 
  FROM 
      query_history history 
  WHERE 
      history.hostname='mysql.database-server-001.linkedin.com' 
      AND ts>='2020-03-11 09:00:00' 
      AND ts<='2020-03-11 10:00:00';
    
  SELECT 
      info.checksum,
      info.firstseen AS first_seen,
      info.fingerprint,
      info.sample,
      SUM(count) as count,
      ROUND(((SUM(count)/@count)*100),2) AS pct_total_query_count,
      ROUND((SUM(count)/(TIME_TO_SEC(TIMEDIFF(MAX(history.ts),MIN(history.ts))))),2) AS qps,
      ROUND((SUM(querytime)/SUM(count)),6) AS avg_query_time,
      ROUND(SUM(querytime),6) AS sum_query_time,
      ROUND((SUM(querytime)/@qt)*100,2) AS pct_total_query_time,
      MIN(info.mintime) AS min_query_time,
      MAX(info.maxtime) AS max_query_time
  FROM 
      query_history history 
  JOIN     
      query_info info 
  ON 
      info.checksum=history.checksum 
      AND info.hostname=history.hostname 
  WHERE 
      info.hostname='mysql.database-server-001.linkedin.com' 
      AND ts>='2020-03-11 09:00:00' 
      AND ts<='2020-03-11 10:00:00' 
  GROUP BY 
      info.checksum 
  ORDER BY
      pct_total_query_time DESC 
  LIMIT 5\G
  ```

* Trend for a particular query
  ```
  SELECT 
      UNIX_TIMESTAMP(ts),
      ROUND(querytime/count,6) 
  FROM 
      query_history history 
  WHERE 
      history.checksum='D22AB75FA3CC05DC' 
      AND history.hostname='mysql.database-server-001.linkedin.com' 
      AND ts>='2020-03-11 09:00:00' 
      AND ts<='2020-03-11 10:00:00';
  ```
* Queries fired from a particular IP
  ```
  SELECT
      info.checksum,
      info.fingerprint,
      info.sample
  FROM 
      query_history history 
  JOIN     
      query_info info 
  ON 
      info.checksum=history.checksum 
      AND info.hostname=history.hostname 
  WHERE 
      history.src='10.251.225.27'
  LIMIT 5;
  ```
* New queries on a particular day
  ```
  SELECT
      info.firstseen,
      info.checksum,
      info.fingerprint,
      info.sample
  FROM   
      query_info info 
  WHERE 
      info.hostname = 'mysql.database-server-001.linkedin.com' 
      AND info.firstseen >= '2020-03-10 00:00:00'
      AND info.firstseen < '2020-03-11 00:00:00'
  LIMIT 5;
  ```

## Limitations
* As of now, it works only for MySQL.

* Does not account for 
   * SSL
   * Compressed packets
   * Replication traffic
   * Big queries for performance reasons

* The number of unique query fingerprints should be limited (like <100K). For example if there is some blob in the query and the tool is unable to generate the correct fingerprint, it will lead to a huge number of fingerprints and can increase the memory footprint of QueryAnalyzerAgent.<br /><br />
  Another example is if you are using Github's Orchestrator in pseudo GTID mode, it generates queries like 
  ```
  drop view if exists `_pseudo_gtid_`.`_asc:5d8a58c6:0911a85c:865c051f49639e79`
  ```

  The fingerprint for those queries will be unique each time and it will lead to more number of distinct queries in QueryAnalyzerAgent. Code to ignore those queries is commented, uncomment if needed.

* Test the performance of QueryAnalyzerAgent in your staging environment before running on production. 
