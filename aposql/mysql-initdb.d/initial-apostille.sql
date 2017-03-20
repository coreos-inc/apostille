CREATE DATABASE IF NOT EXISTS `apostille`;
CREATE DATABASE IF NOT EXISTS `apostille_root`;

CREATE USER "server"@"%" IDENTIFIED BY "12345";
GRANT
	ALL PRIVILEGES ON `apostille`.*
	TO "server"@"%";

-- Read Only user for apostille_root
CREATE USER "readonlyuser"@"%" IDENTIFIED BY "12345";
GRANT
	SELECT ON `apostille_root`.*
	TO "readonlyuser"@"%";

-- Write user for apostille_root
CREATE USER "server_root"@"%" IDENTIFIED BY "54321";
GRANT
	ALL PRIVILEGES ON `apostille_root`.*
	TO "server_root"@"%";