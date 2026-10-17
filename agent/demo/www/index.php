<?php
// Company profile — lab victim app. Deliberately vulnerable so attacks produce
// real error/access log lines. Never deploy this anywhere real.
$db = @new mysqli('localhost', 'cms', 'cms-lAB-pass', 'company_profile');
?>
<!doctype html>
<html>
<head><title>Nusantara Corp — Company Profile</title></head>
<body style="font-family:system-ui;max-width:820px;margin:40px auto">
  <h1>Nusantara Corp</h1>
  <p>Company profile demo application.</p>
  <ul>
    <li><a href="/about.php">About</a></li>
    <li><a href="/staff.php?id=1">Staff directory</a></li>
    <li><a href="/login.php">Staff login</a></li>
    <li><a href="/contact.php">Contact</a></li>
    <li><a href="/gallery.php?page=about">Gallery</a></li>
  </ul>
  <?php if ($db && !$db->connect_error): ?>
  <p style="color:#080">Connected to company_profile database.</p>
  <?php else: ?>
  <p style="color:#a00">Database unavailable.</p>
  <?php endif; ?>
</body>
</html>
