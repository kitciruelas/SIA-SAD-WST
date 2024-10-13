<?php
session_start();

if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("location: login.html");
    exit;
}
include 'config.php';

// SQL query to count users
$sql = "SELECT COUNT(*) AS user_count FROM users";
$result = $conn->query($sql);

// Fetch the result
if ($result->num_rows > 0) {
    // Output data of each row
    $row = $result->fetch_assoc();
    $userCount = $row['user_count'];
} else {
    $userCount = 0; // No users found
}


// SQL query to fetch only displayed announcements
$sql = "SELECT * FROM announce WHERE is_displayed = 1";
$result = mysqli_query($conn, $sql);

$announcements = [];
if ($result) {
    while ($row = mysqli_fetch_assoc($result)) {
        $announcements[] = $row; // Collect displayed announcements
    }
}

// Initialize the announcement variable
$announcement = null;

// Check if an announcement ID is provided
if (isset($_GET['id'])) {
    $announcementId = intval($_GET['id']);
    $sql = "SELECT * FROM announce WHERE announcementId = $announcementId";
    $result = mysqli_query($conn, $sql);
    
    if ($result && mysqli_num_rows($result) > 0) {
        $announcement = mysqli_fetch_assoc($result);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="dashboard.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="menu" id="hamburgerMenu">
            <i class="fas fa-bars"></i> <!-- Hamburger menu icon -->
        </div>

        <div class="sidebar-nav">
            <a href="#" class="nav-link active" ><i class="fas fa-user-cog"></i> <span>Admin</span></a>
            <a href="manageuser.php" class="nav-link"><i class="fas fa-users"></i> <span>Manage User</span></a>
        </div>
        
        <div class="logout">
            <a href="logout.php"><i class="fas fa-sign-out-alt"></i> <span>Logout</span></a>
        </div>
    </div>

    <!-- Top bar -->
    <div class="topbar">
        <h2>Welcome to Dormio, <?php echo htmlspecialchars($_SESSION["username"]); ?>!</h2>

       <!-- Profile Button Icon -->
       <button id="openEditUserModal" class="editUserModal">
    <i class="fa fa-user"></i> Edit Profile</button>

<!-- Edit User Modal -->
<div id="editUserModal" class="modal" style="display: none;">
    <div class="addmodal-content" role="dialog" aria-labelledby="editUserModalTitle" aria-hidden="true">
        <span class="close" id="closeEditModal" aria-label="Close Modal">&times;</span>
        <h2 id="editUserModalTitle">Edit Profile</h2>
        <form method="POST" action="" onsubmit="return validateForm();">
            <input type="hidden" id="editUserId" name="user_id">
            <div class="form-grid">
                <div class="form-group">
                    <label for="editFname">First Name:</label>
                    <input type="text" id="editFname" name="Fname" required>
                </div>
                <div class="form-group">
                    <label for="editLname">Last Name:</label>
                    <input type="text" id="editLname" name="Lname" required>
                </div>
                <div class="form-group">
                    <label for="editMI">Middle Initial:</label>
                    <input type="text" id="editMI" name="MI">
                </div>
                <div class="form-group">
                    <label for="editAge">Age:</label>
                    <input type="number" id="editAge" name="Age" required>
                </div>
                <div class="form-group">
                    <label for="editAddress">Address:</label>
                    <input type="text" id="editAddress" name="Address" required>
                </div>
                <div class="form-group">
                    <label for="editContact">Contact Number:</label>
                    <input type="text" id="editContact" name="contact" required pattern="[0-9]{10,11}" title="Please enter a valid contact number (10-11 digits)">
                </div>
                <div class="form-group">
                    <label for="editSex">Sex:</label>
                    <select id="editSex" name="Sex">
                        <option value="Male">Male</option>
                        <option value="Female">Female</option>
                    </select>
                </div>
                <div class="form-group">

                
                </div>
            </div>
            <button type="submit" name="edit_user">Update</button>
        </form>
    </div>
</div>


    </div>
                <!-- ANNOUNCEMENT -->

    
    <div class="main-content">
        <div class="announcement-box">
            <h2><i class="fas fa-bullhorn announcement-icon"></i> Announcements</h2>
            
            <div class="announcement-container">
    <?php if (!empty($announcements)): ?>
        <?php foreach ($announcements as $announcement): ?>
            <div class="announcement-item">
                <h3><?= htmlspecialchars($announcement['title']) ?></h3>
                <p><?= htmlspecialchars($announcement['content']) ?></p>
                <p>Date Published: <?= htmlspecialchars($announcement['date_published']) ?></p>
            </div>
        <?php endforeach; ?>
    <?php else: ?>
        <p>No announcements to display.</p>
    <?php endif; ?>

            <a href="announcement.php" class="nav-link"><i class="fas fa-plus-circle"></i> <span>See Announcement</span></a>
    </div>
        </div>

        <div class="boxes">
            <div class="user-box">
                <p>
                    <a href="manageuser.php"><strong>Number of Users:</strong></a>
                    <span class="user-count"><?php echo $userCount; ?></span>
                </p>
            </div>


            <div class="room-box">
            <p>
                <strong>Number of Rooms:</strong>
                <!-- Add dynamic room count here -->
            </p>
        </div>
        <div class="checkin-box">
            <p>
                <strong>Number of Check-ins:</strong>
                <!-- Add dynamic check-in count here -->
            </p>
        </div>
        <div class="user-box">
            <p>
                <a href="manageuser.php"><strong>Number of Users:</strong></a>
                <!-- Add dynamic user count here -->
            </p>
        </div>
        <div class="room-box">
            <p>
                <strong>Number of Rooms:</strong>
                <!-- Add dynamic room count here -->
            </p>
        </div>
        <div class="checkin-box">
            <p>
                <strong>Number of Check-ins:</strong>
                <!-- Add dynamic check-in count here -->
            </p>
        </div>
        </div>

       
    </div>
</div>

    <!-- Script -->

    <script>
        document.getElementById('openEditUserModal').onclick = function() {
    document.getElementById('editUserModal').style.display = 'flex'; // Show modal
};

document.getElementById('closeEditModal').onclick = function() {
    document.getElementById('editUserModal').style.display = 'none'; // Hide modal
};

// Close the modal when clicking outside of it
window.onclick = function(event) {
    const modal = document.getElementById('editUserModal');
    if (event.target == modal) {
        modal.style.display = 'none'; // Hide modal
    }
};


// Form validation function
function validateForm() {
    let fname = document.getElementById('editFname').value;
    let lname = document.getElementById('editLname').value;
    let age = document.getElementById('editAge').value;
    let contact = document.getElementById('editContact').value;
    
    if (!fname || !lname || !age || !contact) {
        alert('Please fill out all required fields.');
        return false;
    }
    
    return true;
}

    
</script>
<script>
    const hamburgerMenu = document.getElementById('hamburgerMenu');
    const sidebar = document.getElementById('sidebar');

    // Initially set sidebar to collapsed
    sidebar.classList.add('collapsed');

    hamburgerMenu.addEventListener('click', function() {
        sidebar.classList.toggle('collapsed');  // Toggle sidebar collapse state
        
        // Change the icon based on the sidebar state
        const icon = hamburgerMenu.querySelector('i');
        if (sidebar.classList.contains('collapsed')) {
            icon.classList.remove('fa-times'); // Change to hamburger icon
            icon.classList.add('fa-bars');
        } else {
            icon.classList.remove('fa-bars'); // Change to close icon
            icon.classList.add('fa-times');
        }
    });
  // Get all sidebar links
  const sidebarLinks = document.querySelectorAll('.sidebar a');

  // Loop through each link
  sidebarLinks.forEach(link => {
    link.addEventListener('click', function() {
      // Remove the active class from all links
      sidebarLinks.forEach(link => link.classList.remove('active'));
      
      // Add the active class to the clicked link
      this.classList.add('active');
    });
  });
  
  
</script>
</body>
</html>



