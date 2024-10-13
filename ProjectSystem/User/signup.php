<?php
// Include configuration file for DB connection variables
include 'config.php';

// Check if the form was submitted via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve and sanitize form data
    $fname = htmlspecialchars(trim($_POST['fname']));
    $lname = htmlspecialchars(trim($_POST['lname']));
    $mi = htmlspecialchars(trim($_POST['mi']));
    $age = (int)$_POST['age'];
    $address = htmlspecialchars(trim($_POST['address']));
    $contact = htmlspecialchars(trim($_POST['contact']));
    $sex = htmlspecialchars(trim($_POST['sex']));
    $role = htmlspecialchars(trim($_POST['role']));
    $email = htmlspecialchars(trim($_POST['email']));
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Validate if passwords match
    if ($password !== $confirm_password) {
        echo "<script>alert('Passwords do not match. Please try again.'); window.history.back();</script>";
        exit;
    }

    // Hash the password using bcrypt
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Prepare the SQL statement
    $stmt = $conn->prepare("INSERT INTO users (fname, lname, mi, age, address, contact, sex, role, email, password) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

    // Bind the parameters
    $stmt->bind_param("sssiisssss", $fname, $lname, $mi, $age, $address, $contact, $sex, $role, $email, $hashed_password);

    // Execute the statement
    if ($stmt->execute()) {
        // If the account creation is successful, alert and redirect to login
        echo "<script>alert('Account successfully created!'); window.location.href = 'login.html';</script>";
    } else {
        // Handle duplicate email error (code 1062 is for duplicate entry in MySQL)
        if ($stmt->errno === 1062) {
            echo "<script>alert('An account with this email already exists. Please use a different email.'); window.history.back();</script>";
        } else {
            echo "<script>alert('An error occurred: " . $stmt->error . "'); window.history.back();</script>";
        }
    }

    // Close the prepared statement and the connection
    $stmt->close();
    $conn->close();
}
?>
