<?php
// Database configuration
$host = 'localhost';
$dbname = 'm&j store';
$username = 'root';
$password = '';

// Create connection
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'register') {
        handleRegistration($pdo);
    } elseif ($action === 'login') {
        handleLogin($pdo);
    }
}

function handleRegistration($pdo) {
    // Get form data
    $firstName = $_POST['firstName'] ?? '';
    $lastName = $_POST['lastName'] ?? '';
    $email = $_POST['email'] ?? '';
    $phone = $_POST['phone'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirmPassword'] ?? '';
    $terms = isset($_POST['terms']);
    $newsletter = isset($_POST['newsletter']);
    
    // Validate required fields
    if (empty($firstName) || empty($lastName) || empty($email) || empty($password) || empty($confirmPassword) || !$terms) {
        redirectWithError('All required fields must be filled and terms must be accepted.');
    }
    
    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        redirectWithError('Please enter a valid email address.');
    }
    
    // Validate password match
    if ($password !== $confirmPassword) {
        redirectWithError('Passwords do not match.');
    }
    
    // Validate password length
    if (strlen($password) < 8) {
        redirectWithError('Password must be at least 8 characters long.');
    }
    
    // Check if email already exists
    try {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            redirectWithError('Email already exists. Please use a different email.');
        }
    } catch(PDOException $e) {
        redirectWithError('Database error: ' . $e->getMessage());
    }
    
    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    
    // Insert user into database
    try {
        $stmt = $pdo->prepare("INSERT INTO users (first_name, last_name, email, phone, password, newsletter, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
        $stmt->execute([$firstName, $lastName, $email, $phone, $hashedPassword, $newsletter ? 1 : 0]);
        
        // Start session and redirect to success page
        session_start();
        $_SESSION['user_id'] = $pdo->lastInsertId();
        $_SESSION['user_email'] = $email;
        $_SESSION['user_name'] = $firstName . ' ' . $lastName;
        
        header('Location: home website.html');
        exit();
    } catch(PDOException $e) {
        redirectWithError('Registration failed: ' . $e->getMessage());
    }
}

function handleLogin($pdo) {
    // Get form data
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $rememberMe = isset($_POST['rememberMe']);
    
    // Validate required fields
    if (empty($email) || empty($password)) {
        redirectWithError('Please enter both email and password.');
    }
    
    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        redirectWithError('Please enter a valid email address.');
    }
    
    // Check user credentials
    try {
        $stmt = $pdo->prepare("SELECT id, first_name, last_name, password FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($password, $user['password'])) {
            // Start session
            session_start();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_email'] = $email;
            $_SESSION['user_name'] = $user['first_name'] . ' ' . $user['last_name'];
            
            // Set remember me cookie if requested
            if ($rememberMe) {
                $cookieValue = base64_encode($user['id'] . ':' . hash('sha256', $user['password']));
                setcookie('remember_me', $cookieValue, time() + (30 * 24 * 60 * 60), '/'); // 30 days
            }
            
            header('Location: home website.html');
            exit();
        } else {
            redirectWithError('Invalid email or password.');
        }
    } catch(PDOException $e) {
        redirectWithError('Login failed: ' . $e->getMessage());
    }
}

function redirectWithError($message) {
    // Store error message in session and redirect back to form
    session_start();
    $_SESSION['error_message'] = $message;
    header('Location: ' . $_SERVER['HTTP_REFERER']);
    exit();
}

// Create users table if it doesn't exist (run this once)
function createUsersTable($pdo) {
    $sql = "CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(50) NOT NULL,
        last_name VARCHAR(50) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(20),
        password VARCHAR(255) NOT NULL,
        newsletter BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )";
    
    try {
        $pdo->exec($sql);
        echo "Users table created successfully.";
    } catch(PDOException $e) {
        echo "Error creating table: " . $e->getMessage();
    }
}

// Uncomment the line below to create the table (run once)
// createUsersTable($pdo);
?>