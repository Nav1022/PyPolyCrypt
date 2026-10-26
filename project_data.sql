-- Reference schema (main.py setup creates this automatically).
CREATE DATABASE IF NOT EXISTS project_data;
USE project_data;

CREATE TABLE IF NOT EXISTS data_table (
    data_id        INT AUTO_INCREMENT PRIMARY KEY,
    number_data    INT NOT NULL,          -- demo plaintext, kept only to verify results
    encrypted_data BLOB NULL,             -- zlib-compressed ciphertext
    hash_sha256    CHAR(64) NULL,         -- integrity hash of encrypted_data
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
