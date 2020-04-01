CREATE USER /*!50706 IF NOT EXISTS*/ 'qan_rw'@'qan_agent_ip' IDENTIFIED BY 'Complex_P@ssw0rd';
GRANT SELECT, INSERT, UPDATE ON `query_analyzer`.* TO 'qan_rw'@'qan_agent_ip';
