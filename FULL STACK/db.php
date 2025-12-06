<?php
// db.php - PDO connection settings
// Copy this into your server (e.g., XAMPP htdocs/waterbilling)

$DB_HOST = '127.0.0.1';
$DB_NAME = 'waterbilling';
$DB_USER = 'root';
$DB_PASS = '';

// JWT secret used to sign tokens. Change this to a strong random value in production.
$JWT_SECRET = 'please_change_this_to_a_long_random_secret';

$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

try {
    $pdo = new PDO("mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4", $DB_USER, $DB_PASS, $options);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed', 'details' => $e->getMessage()]);
    exit;
}
