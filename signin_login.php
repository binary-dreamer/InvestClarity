<?PHP

session_start();
include_once 'connectivity.php';
$signup_errors = [];
$login_errors = [];

function is_logged_in() {
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

// Add this logout functionality near the top of your file
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['signup'])) {
        $fname = trim($_POST['fullname']); // `fullname` changed to `fname` in the variable name
        $mail = trim($_POST['email']); // `email` changed to `mail` in the variable name
        $pass = $_POST['password']; // `password` changed to `pass` in the variable name
        $terms = isset($_POST['terms']) ? $_POST['terms'] : '';

        // Validate full name
        if (empty($fname)) {
            $signup_errors[] = "Full name is required";
        }

        // Validate email
        if (empty($mail)) {
            $signup_errors[] = "Email is required";
        } elseif (!filter_var($mail, FILTER_VALIDATE_EMAIL)) {
            $signup_errors[] = "Invalid email format";
        }

        // Validate password
        if (empty($pass)) {
            $signup_errors[] = "Password is required";
        } elseif (strlen($pass) < 8) {
            $signup_errors[] = "Password must be at least 8 characters long";
        }

        // Validate terms acceptance
        if (empty($terms)) {
            $signup_errors[] = "You must accept the terms and conditions";
        }

        if (empty($signup_errors)) {
            // Check if email already exists
            $email_check_query = "SELECT * FROM user_check WHERE mail = ?"; // Change `email` to `mail` in the query
            $stmt = mysqli_prepare($conn, $email_check_query);
            mysqli_stmt_bind_param($stmt, "s", $mail); // Change `email` to `mail` in bind_param
            mysqli_stmt_execute($stmt);
            mysqli_stmt_store_result($stmt);
            if (mysqli_stmt_num_rows($stmt) > 0) {
                $signup_errors[] = "Email already exists. Please use another email.";
            } else {
                // Hash the password for security
                $hashed_password = password_hash($pass, PASSWORD_DEFAULT); // Change `password` to `pass`

                // Insert user into the database
                $insert_query = "INSERT INTO user_check (fname, mail, pass) VALUES (?, ?, ?)"; // Update column names
                $stmt = mysqli_prepare($conn, $insert_query);
                mysqli_stmt_bind_param($stmt, "sss", $fname, $mail, $hashed_password); // Update variable names
                
                if (mysqli_stmt_execute($stmt)) {
                    $_SESSION['success_message'] = "Signup successful!";
                    header("Location:" . $_SERVER['PHP_SELF']);
                    exit();
                } else {
                    $signup_errors[] = "Error inserting user data into the database";
                }
            }
            mysqli_stmt_close($stmt);
        }
    }
    elseif (isset($_POST['login'])) {
        $mail = trim($_POST['email']); // `email` changed to `mail` in the variable name
        $pass = $_POST['password']; // `password` changed to `pass` in the variable name

        // Validate email
        if (empty($mail)) {
            $login_errors[] = "Email is required";
        } elseif (!filter_var($mail, FILTER_VALIDATE_EMAIL)) {
            $login_errors[] = "Invalid email format";
        }

        // Validate password
        if (empty($pass)) {
            $login_errors[] = "Password is required";
        }

        if (empty($login_errors)) {
            // Verify user credentials
            $login_query = "SELECT * FROM user_check WHERE mail = ?"; // Change `email` to `mail` in the query
            $stmt = mysqli_prepare($conn, $login_query);
            mysqli_stmt_bind_param($stmt, "s", $mail); // Change `email` to `mail` in bind_param
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            
            if ($result && mysqli_num_rows($result) > 0) {
                $user = mysqli_fetch_assoc($result);
                if (password_verify($pass, $user['pass'])) {
					 $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_email'] = $user['mail'];
                    $_SESSION['user_name'] = $user['fname'];
                    $_SESSION['logged_in'] = true;
					
                    $_SESSION['success_message'] = "Login successful!";
                    //$_SESSION['user_id'] = $user['id']; // Save user ID in session
                    header("Location:" ); // Redirect to dashboard or desired page
                    exit();
                } else {
                    $login_errors[] = "Incorrect password";
                }
				
            } else {
                $login_errors[] = "No account found with that email";
            }
            mysqli_stmt_close($stmt);
        }
    }
}




?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="description" content="Responsive Login & Registration Form in PHP with validation" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login & Signup Form PHP</title>
    <link rel="stylesheet" href="style.css" />
</head>
<body>
    <section class="wrapper">
        <?php
        if (isset($_SESSION['success_message'])) {
            echo "<div class='success-message'>" . $_SESSION['success_message'] . "</div>";
            unset($_SESSION['success_message']);
        }
		if (is_logged_in()) {
            echo "<div class='user-info'>";
            echo "Welcome, " . $_SESSION['user_name'] . "! ";
            echo "<a href='?logout=true'>Logout</a>";
            echo "</div>";
        }
        ?>

        <div class="form signup">
            <header>Signup</header>
            <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
                <input type="text" name="fullname" placeholder="Full name" value="<?php echo isset($_POST['fullname']) ? htmlspecialchars($_POST['fullname']) : ''; ?>" required />
                <input type="text" name="email" placeholder="Email address" value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" required />
                <input type="password" name="password" placeholder="Password" required />
                <div class="checkbox">
                    <input type="checkbox" id="signupCheck" name="terms" <?php echo isset($_POST['terms']) ? 'checked' : ''; ?> />
                    <label for="signupCheck">I accept all terms & conditions</label>
                </div>
                <input type="submit" name="signup" value="Signup" />
                <?php
                if (!empty($signup_errors)) {
                    echo "<div class='error-messages'>";
                    foreach ($signup_errors as $error) {
                        echo "<p>$error</p>";
                    }
                    echo "</div>";
                }
                ?>
            </form>
        </div>

        <div class="form login">
            <header>Login</header>
           <form action=" <?php echo $_SERVER['PHP_SELF']; ?>http://localhost/draft%203/ " method="post">
                <input type="text" name="email" placeholder="Email address" value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" required />
                <input type="password" name="password" placeholder="Password" required />
                <a href="#">Forgot password?</a>
                <input type="submit" name="login" value="login" />
               <?php
                if (!empty($login_errors)) {
                    echo "<div class='error-messages'>";
                    foreach ($login_errors as $error) {
                        echo "<p>$error</p>";
                    }
                    echo "</div>";
                }
                ?>
				
            </form>
        </div>

        <script>
            const wrapper = document.querySelector(".wrapper"),
                signupHeader = document.querySelector(".signup header"),
                loginHeader = document.querySelector(".login header");

            loginHeader.addEventListener("click", () => {
                wrapper.classList.add("active");
            });
            signupHeader.addEventListener("click", () => {
                wrapper.classList.remove("active");
            });
        </script>
    </section>
</body>
</html>