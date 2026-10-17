<?php
// SQL injection on purpose: the id parameter is concatenated straight into the
// query, so a probe like "1 UNION SELECT ..." reaches MySQL and produces a real
// error that lands in the Apache/PHP log.
$db = new mysqli('localhost', 'cms', 'cms-lAB-pass', 'company_profile');
$id = $_GET['id'] ?? '1';
$sql = "SELECT id, username, email FROM staff WHERE id = $id";
$row = null;
$err = null;
$res = @$db->query($sql);
if ($res === false) {
    $err = $db->error;
} elseif ($res) {
    $row = $res->fetch_assoc();
}
?>
<!doctype html>
<html><head><title>Staff</title></head>
<body style="font-family:system-ui;max-width:700px;margin:40px auto">
  <h2>Staff member</h2>
  <?php if ($err): ?>
    <p style="color:#a00">Query failed: <?= htmlspecialchars($err) ?></p>
  <?php elseif ($row): ?>
    <p>Username: <?= htmlspecialchars($row['username']) ?></p>
    <p>Email: <?= htmlspecialchars($row['email'] ?? '') ?></p>
  <?php else: ?>
    <p>No such staff member.</p>
  <?php endif; ?>
  <p><a href="/">Back</a></p>
</body></html>
