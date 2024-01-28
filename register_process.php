<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Result</title>
</head>
<body>
    <?php
    require_once 'config.php';

    $username = $_POST['username'];
    $password = $_POST['password'];
    $captcha = $_POST['g-recaptcha-response'];

    $password_strength = check_password_strength($password);

    if ($password_strength < 3) {
        echo "Password is too weak. Please choose a stronger password.";
        exit();
    }

    if (!validate_captcha($captcha)) {
        echo "reCAPTCHA verification failed. Please try again.";
        exit();
    }

    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $username, $hashed_password);

    if ($stmt->execute()) {
        echo "Registration successful. Please log in.";
    } else {
        echo "Error: " . $sql . "<br>" . $conn->error;
    }

    $stmt->close();
    $conn->close();

    function check_password_strength($password) {
        $strength = 0;

        if (preg_match("/[a-z]/", $password) && preg_match("/[A-Z]/", $password) && preg_match("/[0-9]/", $password) && preg_match("/[!@#$%^&*]/", $password)) {
            $strength = 4;
        } elseif (preg_match("/[a-z]/", $password) && preg_match("/[A-Z]/", $password) && preg_match("/[0-9]/", $password)) {
            $strength = 3;
        } elseif (preg_match("/[a-z]/", $password) && preg_match("/[A-Z]/", $password) && preg_match("/[!@#$%^&*]/", $password)) {
            $strength = 3;
        } elseif (preg_match("/[a-z]/", $password) && preg_match("/[0-9]/", $password) && preg_match("/[!@#$%^&*]/", $password)) {
            $strength = 3;
        } elseif (preg_match("/[A-Z]/", $password) && preg_match("/[0-9]/", $password) && preg_match("/[!@#$%^&*]/", $password)) {
            $strength = 3;
        } elseif (strlen($password) > 7) {
            $strength = 2;
        }

        return $strength;
    }

    function validate_captcha($captcha) {
        $response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=your_secret_key&response=" . $captcha);
        $response_keys = json_decode($response, true);

        if (intval($response_keys["success"]) === 1) {
            return true;
        } else {
            return false;
        }
    }
    ?>
</body>
</html>