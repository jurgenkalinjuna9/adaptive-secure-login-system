-- ============================================================
-- Adaptive Secure Login System
-- Database Schema
-- MSc Cybersecurity Dissertation Prototype
-- ============================================================

-- Create the database if it does not already exist.
CREATE DATABASE IF NOT EXISTS adaptive_login;

-- Select the database for the following table definitions.
USE adaptive_login;


-- ============================================================
-- USERS
-- Stores registered user accounts.
-- Passwords are stored as hashes rather than plaintext.
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY (username)
);


-- ============================================================
-- LOGIN ATTEMPTS
-- Records authentication activity and adaptive risk decisions.
--
-- user_id is nullable so attempts involving an unknown username
-- can still be recorded.
-- ============================================================

CREATE TABLE IF NOT EXISTS login_attempts (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NULL,
    username VARCHAR(100) NULL,
    ip_address VARCHAR(45) NULL,
    device_id VARCHAR(255) NULL,
    success TINYINT(1) NOT NULL,
    failed_attempts INT DEFAULT 0,
    risk_score INT DEFAULT 0,
    risk_level VARCHAR(20) NULL,
    action_taken VARCHAR(50) NULL,
    response_time_ms DECIMAL(10,2) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    FOREIGN KEY (user_id)
        REFERENCES users(id)
);


-- ============================================================
-- TRUSTED DEVICES
-- Stores browser device identifiers previously trusted
-- following successful or verified authentication.
-- ============================================================

CREATE TABLE IF NOT EXISTS trusted_devices (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    FOREIGN KEY (user_id)
        REFERENCES users(id)
);


-- ============================================================
-- TRUSTED IP ADDRESSES
-- Stores IP addresses previously trusted for registered users.
-- ============================================================

CREATE TABLE IF NOT EXISTS trusted_ips (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    FOREIGN KEY (user_id)
        REFERENCES users(id)
);
