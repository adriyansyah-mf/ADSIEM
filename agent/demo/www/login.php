<?php
// Login form. Wrong credentials are logged by Apache AND counted in MySQL,
// so brute force produces a real 401 trail the SIEM can threshold on.
session_start();
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $db = new mysqli('localhost', 'cms', 'cms-lAB-pass', 'company_profile');
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    $stmt = $db->prepare("SELECT id FROM staff WHERE username = ? AND password = ?");
    $stmt->bind_param('ss', $u, $p);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        $_SESSION['user'] = $u;
        $msg = 'Welcome, ' . htmlspecialchars($u);
    } else {
        http_response_code(401);
        $msg = 'Invalid credentials';
    }
}
?>
<!doctype html>
<html><head><title>Staff Login</title></head>
<body style="font-family:system-ui;max-width:420px;margin:60px auto">
  <h2>Staff Login</h2>
  <?php if ($msg): ?><p style="color:#a00"><?= $msg ?></p><?php endif; ?>
  <form method="post">
    <p><input name="username" placeholder="username" style="width:100%;padding:6px"></p>
    <p><input name="password" type="password" placeholder="password" style="width:100%;padding:6px"></p>
    <p><button type="submit">Sign in</button></p>
  </form>
  <p><a href="/">Back</a></p>
</body></html>
