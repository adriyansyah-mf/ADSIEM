<?php
// Local file inclusion on purpose: page= is passed to include() with no
// allow-list, so ../../../../etc/passwd is attempted and logged.
$page = $_GET['page'] ?? 'about';
$target = __DIR__ . '/' . $page . '.php';
$wrapped = @file_get_contents($page);
if ($wrapped !== false) {
    echo "<pre>" . htmlspecialchars(substr((string) $wrapped, 0, 2000)) . "</pre>";
} elseif (is_file($target)) {
    include $target;
} else {
    http_response_code(404);
    echo "<p>Page not found: " . htmlspecialchars($page) . "</p>";
}
