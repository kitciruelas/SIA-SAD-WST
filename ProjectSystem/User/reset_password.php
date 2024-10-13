<?php
// Include database connection
include 'config.php';

// Check if the request method is POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Retrieve user inputs and sanitize them
    $email = trim($_POST['email']);
    $new_pass = trim($_POST['new_pass']);
    $confirm_pass = trim($_POST['confirm_pass']);

    // Check if new password and confirm password match
    if ($new_pass === $confirm_pass) {
        // Prepare and bind the SQL statement to check if the email exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
        if ($stmt === false) {
            // Error handling for statement preparation failure
            echo "<script>alert('Failed to prepare the statement.'); window.location.href='reset_password.html';</script>";
            exit;
        }
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        // Check if the email exists
        if ($result->num_rows > 0) {
            // Hash the new password
            $hashed_pass = password_hash($new_pass, PASSWORD_DEFAULT);
            
            //Update the password
            $stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");

            if ($stmt === false) {
                // Error handling for statement preparation failure
                echo "<script>alert('Failed to prepare the statement for update.'); window.location.href='reset_password.html';</script>";
                exit;
            }
            $stmt->bind_param("ss", $hashed_pass, $email);

            // Execute the statement and check for success
            if ($stmt->execute()) {
                // Success message
                echo "<script>alert('Password reset successfully!'); window.location.href='login.html';</script>";
            } else {
                // Error message
                echo "<script>alert('Error: " . htmlspecialchars($stmt->error) . "'); </script>";
            }
        } else {
            // Email not found
            echo "<script>alert('Email not found! Please try again.'); window.location.href='forgot-password.html';</script>";
        }

        $stmt->close();
    } else {
        // Passwords do not match
        echo "<script>alert('Passwords do not match! Please try again.'); window.location.href='forgot-password.html';</script>";
    }
}

// Close the database connection
$conn->close();
?>
