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

CREATE TABLE `channels` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `deleted_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `channels` (id, name) VALUES (1, "published"), (2, "staged"), (3, "alternate-rooted"), (4, "quay");

CREATE TABLE `channels_tuf_files` (
  `channel_id` INT(11) NOT NULL,
  `tuf_file_id` INT(11) NOT NULL,
  FOREIGN KEY (channel_id) REFERENCES channels(`id`) ON DELETE CASCADE,
  FOREIGN KEY (tuf_file_id) REFERENCES tuf_files(`id`) ON DELETE CASCADE,
  PRIMARY KEY (tuf_file_id, channel_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- SHA2 function takes the column name or a string as the first parameter, and the
-- hash size as the second argument. It returns a hex string.
UPDATE `tuf_files` SET `sha256` = SHA2(`data`, 256);
