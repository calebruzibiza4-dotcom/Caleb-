<?php
// test-db.php - Diagnose database connection issues
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "=== Water Billing System - Database Diagnostics ===\n\n";

require_once __DIR__ . '/db.php';

echo "✓ PDO connection successful\n\n";

// Test if users table exists
try {
    $result = $pdo->query("SELECT COUNT(*) as cnt FROM users");
    $count = $result->fetch();
    echo "✓ Users table exists. Records: " . $count['cnt'] . "\n";
} catch (Exception $e) {
    echo "✗ Users table error: " . $e->getMessage() . "\n";
    echo "  → Run waterbilling-modern.sql first via phpMyAdmin or MySQL CLI\n";
    exit(1);
}

// Test if owners table exists
try {
    $result = $pdo->query("SELECT COUNT(*) as cnt FROM owners");
    $count = $result->fetch();
    echo "✓ Owners table exists. Records: " . $count['cnt'] . "\n";
} catch (Exception $e) {
    echo "✗ Owners table error: " . $e->getMessage() . "\n";
    exit(1);
}

// Test if bills table exists
try {
    $result = $pdo->query("SELECT COUNT(*) as cnt FROM bills");
    $count = $result->fetch();
    echo "✓ Bills table exists. Records: " . $count['cnt'] . "\n";
} catch (Exception $e) {
    echo "✗ Bills table error: " . $e->getMessage() . "\n";
    exit(1);
}

echo "\n✓ All tables found!\n";
echo "\nTo create a test user, run:\n";
echo "  php create_user.php testuser testpass\n";
echo "\nThen try logging in with those credentials.\n";
