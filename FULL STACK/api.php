<?php
// api.php - Simple JSON API for modernized water billing
// Place alongside `db.php` and enable via XAMPP (http://localhost/your-folder/api.php)

error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: application/json; charset=utf-8');
// Adjust CORS for development — restrict in production
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/db.php';

if (!isset($pdo)) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection not initialized']);
    exit;
}

$path = isset($_GET['path']) ? rtrim($_GET['path'], '/') : '';
$method = $_SERVER['REQUEST_METHOD'];

// Helper: read JSON body
function body() {
    return json_decode(file_get_contents('php://input'), true) ?: [];
}

// JWT helpers (simple, no external libs)
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
# Run from your workspace directory
cd "C:\Users\T R U T H\OneDrive\Documents\FULL STACK"
php test-db.php

function base64url_decode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) $data .= str_repeat('=', 4 - $remainder);
    return base64_decode(strtr($data, '-_', '+/'));
}

function generate_jwt($payload, $secret, $expireSeconds = 3600) {
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    $payload['iat'] = time();
    $payload['exp'] = time() + $expireSeconds;
    $header_b = base64url_encode(json_encode($header));
    $payload_b = base64url_encode(json_encode($payload));
    $sig = hash_hmac('sha256', "$header_b.$payload_b", $secret, true);
    $sig_b = base64url_encode($sig);
    return "$header_b.$payload_b.$sig_b";
}

function validate_jwt($token, $secret) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return false;
    list($h, $p, $s) = $parts;
    $sig = base64url_decode($s);
    $valid = hash_hmac('sha256', "$h.$p", $secret, true);
    if (!hash_equals($valid, $sig)) return false;
    $payload = json_decode(base64url_decode($p), true);
    if (!$payload) return false;
    if (isset($payload['exp']) && time() > $payload['exp']) return false;
    return $payload;
}

// Get bearer token from Authorization header
function get_bearer_token() {
    $headers = null;
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers = trim($_SERVER['HTTP_AUTHORIZATION']);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }
    if (!$headers) return null;
    if (preg_match('/Bearer\s+(.*)$/i', $headers, $matches)) return $matches[1];
    return null;
}

// Require authentication for protected routes
function require_auth() {
    global $JWT_SECRET;
    $token = get_bearer_token();
    if (!$token) {
        http_response_code(401);
        echo json_encode(['error' => 'Missing token']);
        exit;
    }
    $payload = validate_jwt($token, $JWT_SECRET);
    if (!$payload) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid or expired token']);
        exit;
    }
    return $payload;
}

// Router
switch (true) {
    case $path === 'register' && $method === 'POST':
        register($pdo);
        break;

    case $path === 'login' && $method === 'POST':
        login($pdo);
        break;

    case $path === 'change-credentials' && $method === 'POST':
        $user = require_auth();
        changeCredentials($pdo, $user);
        break;

    case $path === 'owners' && $method === 'GET':
        $user = require_auth();
        getOwners($pdo);
        break;

    case $path === 'owners' && $method === 'POST':
        $user = require_auth();
        createOwner($pdo);
        break;

    case $path === 'bills' && $method === 'GET':
        $user = require_auth();
        getBills($pdo);
        break;

    case $path === 'bills' && $method === 'POST':
        $user = require_auth();
        createBill($pdo);
        break;

    default:
        http_response_code(404);
        echo json_encode(['error' => 'Not found']);
        break;
}
function changeCredentials($pdo, $user) {
    $data = body();
    $fields = [];
    $params = [];
    if (!empty($data['username'])) {
        $fields[] = 'username = ?';
        $params[] = $data['username'];
    }
    if (!empty($data['password'])) {
        $fields[] = 'password_hash = ?';
        $params[] = password_hash($data['password'], PASSWORD_DEFAULT);
    }
    if (empty($fields)) {
        http_response_code(400);
        echo json_encode(['error' => 'No changes provided']);
        return;
    }
    $params[] = $user['sub'];
    try {
        $stmt = $pdo->prepare('UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = ?');
        $stmt->execute($params);
        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Could not update credentials', 'details' => $e->getMessage()]);
    }
}

function register($pdo) {
    $data = body();
    if (empty($data['username']) || empty($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'username and password required']);
        return;
    }
    $hash = password_hash($data['password'], PASSWORD_DEFAULT);
    try {
        $stmt = $pdo->prepare('INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)');
        $stmt->execute([$data['username'], $hash, $data['display_name'] ?? null]);
        echo json_encode(['id' => $pdo->lastInsertId()]);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Could not create user', 'details' => $e->getMessage()]);
    }
}

function login($pdo) {
    global $JWT_SECRET;
    $data = body();
    if (empty($data['username']) || empty($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing credentials']);
        return;
    }
    $stmt = $pdo->prepare('SELECT id, username, password_hash, display_name FROM users WHERE username = ? LIMIT 1');
    $stmt->execute([$data['username']]);
    $user = $stmt->fetch();
    if (!$user || !password_verify($data['password'], $user['password_hash'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid username or password']);
        return;
    }
    $token = generate_jwt(['sub' => $user['id'], 'username' => $user['username']], $JWT_SECRET, 3600);
    echo json_encode(['token' => $token, 'user' => ['id' => $user['id'], 'username' => $user['username'], 'display_name' => $user['display_name']]]);
}

function getOwners($pdo) {
    $stmt = $pdo->query('SELECT id, lname, fname, mi, address, contact FROM owners ORDER BY lname, fname');
    $owners = $stmt->fetchAll();
    echo json_encode($owners);
}

function createOwner($pdo) {
    $data = body();
    if (!$data || empty($data['lname']) || empty($data['fname'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid owner data']);
        return;
    }
    $stmt = $pdo->prepare('INSERT INTO owners (lname, fname, mi, address, contact) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([
        $data['lname'],
        $data['fname'],
        $data['mi'] ?? null,
        $data['address'] ?? null,
        $data['contact'] ?? null,
    ]);
    echo json_encode(['id' => $pdo->lastInsertId()]);
}

function getBills($pdo) {
    $sql = "SELECT b.id, b.owner_id, o.lname, o.fname, b.prev_reading, b.pres_reading, b.consumption, b.price, b.date
            FROM bills b
            JOIN owners o ON o.id = b.owner_id
            ORDER BY b.date DESC LIMIT 200";
    $stmt = $pdo->query($sql);
    $bills = $stmt->fetchAll();
    echo json_encode($bills);
}

function createBill($pdo) {
    $data = body();
    $required = ['owner_id','prev_reading','pres_reading','price'];
    foreach ($required as $r) {
        if (!isset($data[$r])) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing field: ' . $r]);
            return;
        }
    }
    $stmt = $pdo->prepare('INSERT INTO bills (owner_id, prev_reading, pres_reading, price, date) VALUES (?, ?, ?, ?, ? )');
    $stmt->execute([
        (int)$data['owner_id'],
        (int)$data['prev_reading'],
        (int)$data['pres_reading'],
        number_format((float)$data['price'], 2, '.', ''),
        $data['date'] ?? date('Y-m-d H:i:s')
    ]);
    echo json_encode(['id' => $pdo->lastInsertId()]);
}
