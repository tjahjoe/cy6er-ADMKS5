CREATE TABLE `ssh_logs` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `ip` VARCHAR(45) NOT NULL,
    `user` VARCHAR(100) NOT NULL,
    `status` VARCHAR(20) NOT NULL,
    `timestamp` DATETIME NOT NULL,
    PRIMARY KEY (`id`),

    CONSTRAINT `fk_ip_status`
        FOREIGN KEY (`ip`) REFERENCES `ip_status`(`ip`)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);