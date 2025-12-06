<?php
// create_user.php - CLI helper to create a user quickly
// Usage from command line (PowerShell):
// php create_user.php username password "Display Name"

require_once __DIR__ . '/db.php';

if (php_sapi_name() !== 'cli') {
    echo "This script must be run from the command line.\n";
    exit(1);
}

if ($argc < 3) {
    echo "Usage: php create_user.php username password [Display Name]\n";
    exit(1);
}

$username = $argv[1];
$password = $argv[2];
$display = $argv[3] ?? null;

$hash = password_hash($password, PASSWORD_DEFAULT);
try {
    $stmt = $pdo->prepare('INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)');
    $stmt->execute([$username, $hash, $display]);
    echo "User created with ID: " . $pdo->lastInsertId() . "\n";
} catch (Exception $e) {
    echo "Failed to create user: " . $e->getMessage() . "\n";
}
