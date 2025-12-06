CREATE TABLE `wazuh_logs` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `rule_id` VARCHAR(50),
    `rule_desc` TEXT,
    `severity` INT,
    `target` VARCHAR(100),
    `agent_ip` VARCHAR(45),
    `attacker_ip` VARCHAR(45) NOT NULL,
    `log_raw` LONGTEXT,
    `timestamp` DATETIME,
    `monitor` VARCHAR(100),
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT `fk_attacker_ip`
        FOREIGN KEY (`attacker_ip`)
        REFERENCES `ip_status` (`ip`)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);
