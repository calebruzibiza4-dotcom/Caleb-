-- Modernized migration for `waterbilling` (InnoDB, proper types, constraints)
-- Import this file into phpMyAdmin or run via MySQL client

DROP DATABASE IF EXISTS `waterbilling`;
CREATE DATABASE `waterbilling` CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci;
USE `waterbilling`;

-- Owners table
CREATE TABLE `owners` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `lname` VARCHAR(100) NOT NULL,
  `fname` VARCHAR(100) NOT NULL,
  `mi` VARCHAR(10) DEFAULT NULL,
  `address` VARCHAR(255) DEFAULT NULL,
  `contact` VARCHAR(30) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Bills table (previously `bill`)
CREATE TABLE `bills` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `owner_id` INT UNSIGNED NOT NULL,
  `prev_reading` INT NOT NULL DEFAULT 0,
  `pres_reading` INT NOT NULL DEFAULT 0,
  `consumption` INT AS (pres_reading - prev_reading) STORED,
  `price` DECIMAL(10,2) NOT NULL DEFAULT 0.00,
  `date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX (`owner_id`),
  CONSTRAINT `fk_bills_owner` FOREIGN KEY (`owner_id`) REFERENCES `owners`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Users table with password hashing
CREATE TABLE `users` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(80) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `display_name` VARCHAR(120) DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sample data
INSERT INTO `owners` (`lname`, `fname`, `mi`, `address`, `contact`) VALUES
('Coca','cxvcxv','P','Pardo','12'),
('Wew','asdasd','DF','Asd','123445');

INSERT INTO `bills` (`owner_id`, `prev_reading`, `pres_reading`, `price`, `date`) VALUES
(1, 12, 20, 10.00, '2013-03-09 07:47:28'),
(2, 12, 23, 10.00, '2013-03-08 00:00:00');

-- NOTE: For users, create account via API which will hash passwords with password_hash().
