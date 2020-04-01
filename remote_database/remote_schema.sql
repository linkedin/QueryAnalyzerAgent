CREATE DATABASE IF NOT EXISTS `query_analyzer`;

CREATE TABLE IF NOT EXISTS `query_analyzer`.`query_info` (
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

CREATE TABLE IF NOT EXISTS `query_analyzer`.`query_history` (
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
