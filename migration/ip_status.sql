CREATE TABLE `ip_status` (
    `ip` VARCHAR(45) NOT NULL,
    `is_blocked` TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (`ip`)
);