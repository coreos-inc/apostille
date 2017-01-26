CREATE DATABASE IF NOT EXISTS `apostille`;

CREATE USER "server"@"%" IDENTIFIED BY "";

GRANT
	ALL PRIVILEGES ON `apostille`.*
	TO "server"@"%";
