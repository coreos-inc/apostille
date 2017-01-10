CREATE TABLE `tuf_files` (
	  `id` int(11) NOT NULL AUTO_INCREMENT,
	  `created_at` timestamp NULL DEFAULT NULL,
	  `updated_at` timestamp NULL DEFAULT NULL,
	  `deleted_at` timestamp NULL DEFAULT NULL,
	  `gun` varchar(255) NOT NULL,
	  `role` varchar(255) NOT NULL,
	  `version` int(11) NOT NULL,
	  `data` longblob NOT NULL,
	  `sha256` CHAR(64) DEFAULT NULL,
	  PRIMARY KEY (`id`),
	  UNIQUE KEY `gun` (`gun`,`role`,`version`),
	  INDEX `sha256` (`sha256`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `alternate_tuf_files` (
	  `id` int(11) NOT NULL AUTO_INCREMENT,
	  `created_at` timestamp NULL DEFAULT NULL,
	  `updated_at` timestamp NULL DEFAULT NULL,
	  `deleted_at` timestamp NULL DEFAULT NULL,
	  `gun` varchar(255) NOT NULL,
	  `role` varchar(255) NOT NULL,
	  `version` int(11) NOT NULL,
	  `data` longblob NOT NULL,
	  `sha256` CHAR(64) DEFAULT NULL,
	  PRIMARY KEY (`id`),
	  UNIQUE KEY `gun` (`gun`,`role`,`version`),
	  INDEX `sha256` (`sha256`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE `change_category` (
    `category` VARCHAR(20) NOT NULL,
    PRIMARY KEY (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `change_category` VALUES ("update"), ("deletion");

CREATE TABLE `changefeed` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
    `gun` varchar(255) NOT NULL,
    `version` int(11) NOT NULL,
    `sha256` CHAR(64) DEFAULT NULL,
    `category` VARCHAR(20) NOT NULL DEFAULT "update",
    PRIMARY KEY (`id`),
    FOREIGN KEY (`category`) REFERENCES `change_category` (`category`),
    INDEX `idx_changefeed_gun` (`gun`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE `alternate_changefeed` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
    `gun` varchar(255) NOT NULL,
    `version` int(11) NOT NULL,
    `sha256` CHAR(64) DEFAULT NULL,
    `category` VARCHAR(20) NOT NULL DEFAULT "update",
    PRIMARY KEY (`id`),
    FOREIGN KEY (`category`) REFERENCES `change_category` (`category`),
    INDEX `idx_changefeed_gun` (`gun`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- SHA2 function takes the column name or a string as the first parameter, and the
-- hash size as the second argument. It returns a hex string.
UPDATE `tuf_files` SET `sha256` = SHA2(`data`, 256);
UPDATE `alternate_tuf_files` SET `sha256` = SHA2(`data`, 256);
