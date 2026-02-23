<?php
declare(strict_types=1);

/**
 * server-panel api.php
 *
 * Env file: /var/www/secret/secret.env
 *
 * Required env vars:
 *   DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS
 *   ADMIN_USER, ADMIN_PASS
 *   WEBHOOK_URL
 *   DIAG_CALLBACK_TOKEN   (shared secret for /speedtest_callback and /diagnostic_callback)
 *   DIALBAG_TOKEN        (stored in env; NOT exposed via API)
 */

header('Content-Type: application/json; charset=utf-8');

$ENV_PATH = '/var/www/secure/secret.env';

/* ---------- helpers ---------- */
function starts_with(string $h, string $n): bool { return $n === '' || strncmp($h, $n, strlen($n)) === 0; }

function fail(int $code, string $msg, ?string $detail = null): void {
  http_response_code($code);
  $out = ['ok' => false, 'error' => $msg];
  if ($detail !== null) $out['detail'] = $detail;
  echo json_encode($out);
  exit;
}

function ok(array $data = []): void {
  echo json_encode(array_merge(['ok' => true], $data));
  exit;
}

function read_env_file(string $path): array {
  if (!is_readable($path)) fail(500, "Env file not readable", $path);
  $out = [];
  $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
  foreach ($lines as $line) {
    $line = trim($line);
    if ($line === '' || starts_with($line, '#')) continue;
    $pos = strpos($line, '=');
    if ($pos === false) continue;
    $k = trim(substr($line, 0, $pos));
    $v = trim(substr($line, $pos + 1));
    if ((starts_with($v, '"') && substr($v, -1) === '"') || (starts_with($v, "'") && substr($v, -1) === "'")) {
      $v = substr($v, 1, -1);
    }
    $out[$k] = $v;
  }
  return $out;
}

function json_input(): array {
  $raw = file_get_contents('php://input');
  if (!$raw) return [];
  $data = json_decode($raw, true);
  return is_array($data) ? $data : [];
}

function session_boot(): void {
  session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
  ]);
  session_start();
}

function is_authed(): bool {
  return !empty($_SESSION['authed']) && $_SESSION['authed'] === true;
}

function require_auth(): void {
  if (!is_authed()) fail(401, 'Not authenticated');
}

function normalize_severity(?string $sev): ?string {
  if ($sev === null) return null;
  $s = strtolower(trim($sev));
  if ($s === '') return null;
  if (in_array($s, ['green','yellow','red'], true)) return $s;
  return null; // unknown -> store NULL
}

function validate_server_key(string $key): void {
  // allow: letters, numbers, underscore, dash, dot; length 1..64
  if ($key === '' || strlen($key) > 64) fail(400, 'Invalid server_key length (1..64)');
  if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]*$/', $key)) {
    fail(400, 'Invalid server_key format (allowed: A-Z a-z 0-9 _ . -)');
  }
}

/* ---------- setup ---------- */
$env = read_env_file($ENV_PATH);

$adminUser = $env['ADMIN_USER'] ?? '';
$adminPass = $env['ADMIN_PASS'] ?? '';

$dbHost = $env['DB_HOST'] ?? '127.0.0.1';
$dbPort = (int)($env['DB_PORT'] ?? '3306');
$dbName = $env['DB_NAME'] ?? '';
$dbUser = $env['DB_USER'] ?? '';
$dbPass = $env['DB_PASS'] ?? '';

$webhookUrl = trim((string)($env['WEBHOOK_URL'] ?? ''));

// ✅ moved secrets to env (no hardcoded constants)
$diagCallbackToken = trim((string)($env['DIAG_CALLBACK_TOKEN'] ?? ''));
$dialbagToken      = trim((string)($env['DIALBAG_TOKEN'] ?? ''));

if ($dbName === '' || $dbUser === '') fail(500, 'DB_NAME/DB_USER missing in env file');
if ($webhookUrl === '') fail(500, 'WEBHOOK_URL missing in env file');
if ($diagCallbackToken === '') fail(500, 'DIAG_CALLBACK_TOKEN missing in env file');

// Stored in env as requested; not used/exposed here. Keep required or relax if you prefer.
// If you want it optional, delete the next line.
if ($dialbagToken === '') fail(500, 'DIALBAG_TOKEN missing in env file');

try {
  $dsn = "mysql:host={$dbHost};port={$dbPort};dbname={$dbName};charset=utf8mb4";
  $pdo = new PDO($dsn, $dbUser, $dbPass, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);
} catch (Throwable $e) {
  fail(500, 'DB connection failed', $e->getMessage());
}

session_boot();

$op = $_GET['op'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

try {
  /* ---------- AUTH ---------- */
  if ($method === 'GET' && $op === 'auth_status') {
    ok(['authed' => is_authed()]);
  }

  if ($method === 'POST' && $op === 'login') {
    $in = json_input();
    $u = (string)($in['username'] ?? '');
    $p = (string)($in['password'] ?? '');

    if ($adminUser === '' || $adminPass === '') fail(500, 'ADMIN_USER/ADMIN_PASS not set in env');

    if (hash_equals($adminUser, $u) && hash_equals($adminPass, $p)) {
      $_SESSION['authed'] = true;
      ok();
    }
    fail(401, 'Invalid username or password');
  }

  if ($method === 'POST' && $op === 'logout') {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
      $params = session_get_cookie_params();
      setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    session_destroy();
    ok();
  }

  /* ---------- CONFIG (NO AUTH REQUIRED) ---------- */
  if ($method === 'GET' && $op === 'config') {
    // Expose only what frontend needs
    ok(['webhook_url' => $webhookUrl]);
  }

  /* ---------- READ (NO AUTH REQUIRED) ---------- */

  if ($method === 'GET' && $op === 'servers') {
    if (is_authed()) {
      $stmt = $pdo->query("
        SELECT id, `key`, label, enabled, public_visible, sort_order
        FROM servers
        WHERE enabled = 1
        ORDER BY sort_order, label
      ");
      ok(['servers' => $stmt->fetchAll()]);
    } else {
      $stmt = $pdo->query("
        SELECT `key`, label
        FROM servers
        WHERE enabled = 1 AND public_visible = 1
        ORDER BY sort_order, label
      ");
      ok(['servers' => $stmt->fetchAll()]);
    }
  }

  if ($method === 'GET' && $op === 'commands') {
    if (is_authed()) {
      $sql = "
        SELECT
          c.id, c.label, c.command, c.confirm_text, c.sort_order, c.enabled, c.public_visible,
          s.`key` AS server_key, s.label AS server_label, s.sort_order AS server_sort_order
        FROM commands c
        JOIN servers s ON s.id = c.server_id
        WHERE s.enabled = 1 AND c.enabled = 1
        ORDER BY s.sort_order, s.label, c.sort_order, c.id
      ";
      $stmt = $pdo->query($sql);
      ok(['commands' => $stmt->fetchAll()]);
    } else {
      $sql = "
        SELECT
          c.id, c.label, c.command, c.confirm_text, c.sort_order,
          s.`key` AS server_key, s.label AS server_label
        FROM commands c
        JOIN servers s ON s.id = c.server_id
        WHERE s.enabled = 1 AND s.public_visible = 1
          AND c.enabled = 1 AND c.public_visible = 1
        ORDER BY s.sort_order, s.label, c.sort_order, c.id
      ";
      $stmt = $pdo->query($sql);
      ok(['commands' => $stmt->fetchAll()]);
    }
  }

  /* ---------- SPEEDTEST (NO AUTH REQUIRED) ---------- */
  if ($method === 'GET' && $op === 'speedtest_status') {
    $st = $pdo->query("SELECT id, down, up, ping, error, updated_at FROM speedtest_results WHERE id = 1 LIMIT 1");
    $row = $st->fetch();
    ok(['result' => $row ?: null]);
  }

  // POST /api.php?op=speedtest_callback&token=...
  if ($method === 'POST' && $op === 'speedtest_callback') {
    $token = (string)($_GET['token'] ?? '');
    if (!hash_equals($diagCallbackToken, $token)) fail(403, 'Forbidden');

    $in = json_input();

    $error = trim((string)($in['error'] ?? ''));

    $down = array_key_exists('down', $in) ? (float)$in['down'] : null;
    $up   = array_key_exists('up', $in)   ? (float)$in['up']   : null;
    $ping = array_key_exists('ping', $in) ? (float)$in['ping'] : null;

    if ($error !== '') {
      $down = null; $up = null; $ping = null;
    } else {
      if ($down === null || $up === null || $ping === null) fail(400, 'down/up/ping required (or provide error)');
    }

    $pdo->beginTransaction();

    $pdo->exec("INSERT INTO speedtest_results (id, down, up, ping, error, updated_at)
                VALUES (1, NULL, NULL, NULL, NULL, NOW())
                ON DUPLICATE KEY UPDATE id = id");

    $st = $pdo->prepare("
      UPDATE speedtest_results
      SET down = ?, up = ?, ping = ?, error = ?, updated_at = NOW()
      WHERE id = 1
      LIMIT 1
    ");
    $st->execute([
      $down,
      $up,
      $ping,
      ($error !== '' ? $error : null),
    ]);

    $pdo->commit();
    ok(['updated' => $st->rowCount()]);
  }

  /* ---------- DIAGNOSTICS (NO AUTH REQUIRED) ---------- */

  if ($method === 'POST' && $op === 'diagnostic_start') {
    $in = json_input();
    $serverKey = trim((string)($in['server_key'] ?? ''));
    if ($serverKey === '') fail(400, 'server_key is required');
    validate_server_key($serverKey);

    $st = $pdo->prepare("SELECT `key`, label, enabled FROM servers WHERE `key` = ? LIMIT 1");
    $st->execute([$serverKey]);
    $srv = $st->fetch();
    if (!$srv || (int)$srv['enabled'] !== 1) fail(400, 'Unknown/disabled server_key');

    $pdo->beginTransaction();

    $check = $pdo->query("SELECT id, server_key, status, created_at FROM diagnostics WHERE status IN ('pending','running') ORDER BY created_at DESC LIMIT 1 FOR UPDATE");
    $running = $check->fetch();

    if ($running) {
      $pdo->commit();
      http_response_code(409);
      echo json_encode([
        'ok' => false,
        'error' => 'A diagnostic is already running. Please wait.',
        'running' => $running
      ]);
      exit;
    }

    $ins = $pdo->prepare("INSERT INTO diagnostics (server_key, status) VALUES (?, 'running')");
    $ins->execute([$serverKey]);
    $id = (int)$pdo->lastInsertId();

    $cleanupSql = "
      DELETE FROM diagnostics
      WHERE server_key = ?
        AND id NOT IN (
          SELECT id FROM (
            SELECT id FROM diagnostics
            WHERE server_key = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 5
          ) x
        )
    ";
    $cl = $pdo->prepare($cleanupSql);
    $cl->execute([$serverKey, $serverKey]);

    $pdo->commit();

    ok([
      'diagnostic_id' => $id,
      'server_key' => $serverKey,
      'server_label' => (string)$srv['label'],
      'status' => 'running'
    ]);
  }

  if ($method === 'GET' && $op === 'diagnostic_status') {
    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) fail(400, 'Missing/invalid id');

    // English-only (no uk_result returned)
    $st = $pdo->prepare("SELECT id, server_key, status, severity, result_text, created_at, finished_at FROM diagnostics WHERE id = ? LIMIT 1");
    $st->execute([$id]);
    $row = $st->fetch();
    if (!$row) fail(404, 'Not found');

    ok(['diagnostic' => $row]);
  }

  if ($method === 'GET' && $op === 'diagnostic_history') {
    $serverKey = trim((string)($_GET['server_key'] ?? ''));
    if ($serverKey === '') fail(400, 'server_key is required');
    validate_server_key($serverKey);

    $st = $pdo->prepare("
      SELECT id, server_key, status, severity, created_at, finished_at,
            LEFT(COALESCE(result_text,''), 500) AS result_preview
      FROM diagnostics
      WHERE server_key = ?
      ORDER BY created_at DESC, id DESC
      LIMIT 5
    ");
    $st->execute([$serverKey]);
    ok(['history' => $st->fetchAll()]);
  }

  // POST /api.php?op=diagnostic_callback&token=...
  if ($method === 'POST' && $op === 'diagnostic_callback') {
    $token = (string)($_GET['token'] ?? '');
    if (!hash_equals($diagCallbackToken, $token)) fail(403, 'Forbidden');

    $in = json_input();
    $rid = (int)($in['request_id'] ?? 0);
    $status = strtolower(trim((string)($in['status'] ?? 'done')));
    $result = (string)($in['result'] ?? '');

    $severity = normalize_severity(isset($in['severity']) ? (string)$in['severity'] : null);

    if ($rid <= 0) fail(400, 'request_id required');
    if (!in_array($status, ['done', 'failed'], true)) $status = 'done';

    // Keep uk_result column (if it exists) wiped to NULL for safety
    $st = $pdo->prepare("
      UPDATE diagnostics
      SET status = ?, severity = ?, result_text = ?, uk_result = NULL, finished_at = NOW()
      WHERE id = ?
      LIMIT 1
    ");
    $st->execute([$status, $severity, $result, $rid]);

    ok(['updated' => $st->rowCount()]);
  }

  /* ---------- ADMIN SETTINGS (AUTH REQUIRED) ---------- */

  if ($method === 'POST' && $op === 'server_settings') {
    require_auth();
    $in = json_input();

    $serverKey = trim((string)($in['server_key'] ?? ''));
    if ($serverKey === '') fail(400, 'server_key is required');
    validate_server_key($serverKey);

    $publicVisible = isset($in['public_visible']) ? (int)((bool)$in['public_visible']) : 1;
    $sortOrder = isset($in['sort_order']) ? (int)$in['sort_order'] : 10;

    $st = $pdo->prepare("UPDATE servers SET public_visible = ?, sort_order = ? WHERE `key` = ? LIMIT 1");
    $st->execute([$publicVisible, $sortOrder, $serverKey]);

    ok(['updated' => $st->rowCount()]);
  }

  if ($method === 'POST' && $op === 'command_settings') {
    require_auth();
    $in = json_input();

    $id = (int)($in['id'] ?? 0);
    if ($id <= 0) fail(400, 'id is required');

    $publicVisible = isset($in['public_visible']) ? (int)((bool)$in['public_visible']) : 1;

    $st = $pdo->prepare("UPDATE commands SET public_visible = ? WHERE id = ? LIMIT 1");
    $st->execute([$publicVisible, $id]);

    ok(['updated' => $st->rowCount()]);
  }

  /* ---------- SERVER MANAGEMENT (AUTH REQUIRED) ---------- */

  if ($method === 'POST' && $op === 'servers_create') {
    require_auth();
    $in = json_input();

    $serverKey = trim((string)($in['server_key'] ?? ''));
    $label = trim((string)($in['label'] ?? ''));

    if ($serverKey === '' || $label === '') fail(400, 'server_key and label are required');
    validate_server_key($serverKey);
    if (mb_strlen($label) > 128) fail(400, 'label too long (max 128)');

    $st = $pdo->prepare("SELECT 1 FROM servers WHERE `key` = ? LIMIT 1");
    $st->execute([$serverKey]);
    if ($st->fetchColumn()) fail(409, 'server_key already exists');

    $ins = $pdo->prepare("
      INSERT INTO servers (`key`, label, enabled, public_visible, sort_order)
      VALUES (?, ?, 1, 1, 10)
    ");
    $ins->execute([$serverKey, $label]);

    ok(['created' => 1, 'id' => (int)$pdo->lastInsertId()]);
  }

  if ($method === 'POST' && $op === 'servers_delete') {
    require_auth();
    $in = json_input();

    $serverKey = trim((string)($in['server_key'] ?? ''));
    if ($serverKey === '') fail(400, 'server_key is required');
    validate_server_key($serverKey);

    $st = $pdo->prepare("SELECT id FROM servers WHERE `key` = ? LIMIT 1");
    $st->execute([$serverKey]);
    $srv = $st->fetch();
    if (!$srv) fail(404, 'Server not found');
    $serverId = (int)$srv['id'];

    $pdo->beginTransaction();
    try {
      $delCmd = $pdo->prepare("DELETE FROM commands WHERE server_id = ?");
      $delCmd->execute([$serverId]);

      $delDiag = $pdo->prepare("DELETE FROM diagnostics WHERE server_key = ?");
      $delDiag->execute([$serverKey]);

      $delSrv = $pdo->prepare("DELETE FROM servers WHERE id = ? LIMIT 1");
      $delSrv->execute([$serverId]);

      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      fail(500, 'Delete failed', $e->getMessage());
    }

    ok([
      'deleted_server' => $delSrv->rowCount(),
      'deleted_commands' => $delCmd->rowCount(),
      'deleted_diagnostics' => $delDiag->rowCount(),
    ]);
  }

  if ($method === 'POST' && $op === 'servers_update_key') {
    require_auth();
    $in = json_input();

    $old = trim((string)($in['old_key'] ?? ''));
    $new = trim((string)($in['new_key'] ?? ''));

    if ($old === '' || $new === '') fail(400, 'old_key and new_key are required');
    if ($old === $new) ok(['updated' => 0]);

    validate_server_key($old);
    validate_server_key($new);

    $st = $pdo->prepare("SELECT id FROM servers WHERE `key` = ? LIMIT 1");
    $st->execute([$old]);
    $srv = $st->fetch();
    if (!$srv) fail(404, 'old_key not found');

    $st2 = $pdo->prepare("SELECT 1 FROM servers WHERE `key` = ? LIMIT 1");
    $st2->execute([$new]);
    if ($st2->fetchColumn()) fail(409, 'new_key already exists');

    $pdo->beginTransaction();
    try {
      $upSrv = $pdo->prepare("UPDATE servers SET `key` = ? WHERE `key` = ? LIMIT 1");
      $upSrv->execute([$new, $old]);

      $upDiag = $pdo->prepare("UPDATE diagnostics SET server_key = ? WHERE server_key = ?");
      $upDiag->execute([$new, $old]);

      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      fail(500, 'Update failed', $e->getMessage());
    }

    ok([
      'updated_servers' => $upSrv->rowCount(),
      'updated_diagnostics' => $upDiag->rowCount()
    ]);
  }

  /* ---------- WRITE (AUTH REQUIRED) ---------- */

  if ($method === 'POST' && $op === 'commands') {
    require_auth();

    $in = json_input();
    $serverKey = trim((string)($in['server_key'] ?? ''));
    $label     = trim((string)($in['label'] ?? ''));
    $command   = trim((string)($in['command'] ?? ''));
    $confirm   = trim((string)($in['confirm_text'] ?? ''));
    $sortOrder = (int)($in['sort_order'] ?? 0);
    $enabled   = isset($in['enabled']) ? (int)((bool)$in['enabled']) : 1;

    $publicVisible = isset($in['public_visible']) ? (int)((bool)$in['public_visible']) : 1;

    if ($serverKey === '' || $label === '' || $command === '') {
      fail(400, 'server_key, label, command are required');
    }
    validate_server_key($serverKey);

    if (mb_strlen($label) > 128) fail(400, 'label too long (max 128)');
    if (mb_strlen($command) > 255) fail(400, 'command too long (max 255)');
    if ($confirm !== '' && mb_strlen($confirm) > 255) fail(400, 'confirm_text too long (max 255)');

    $stmt = $pdo->prepare("SELECT id FROM servers WHERE `key` = ? AND enabled = 1 LIMIT 1");
    $stmt->execute([$serverKey]);
    $row = $stmt->fetch();
    if (!$row) fail(400, 'Unknown/disabled server_key');

    $serverId = (int)$row['id'];

    $stmt = $pdo->prepare("
      INSERT INTO commands (server_id, label, command, confirm_text, sort_order, enabled, public_visible)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    ");
    $stmt->execute([
      $serverId,
      $label,
      $command,
      ($confirm !== '' ? $confirm : null),
      $sortOrder,
      $enabled,
      $publicVisible
    ]);

    ok(['id' => (int)$pdo->lastInsertId()]);
  }

  if ($method === 'DELETE' && $op === 'commands') {
    require_auth();

    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) fail(400, 'Missing/invalid id');

    $stmt = $pdo->prepare("DELETE FROM commands WHERE id = ?");
    $stmt->execute([$id]);

    ok(['deleted' => $stmt->rowCount()]);
  }

  if ($method === 'POST' && $op === 'servers_label') {
    require_auth();

    $in = json_input();
    $serverKey = trim((string)($in['server_key'] ?? ''));
    $label     = trim((string)($in['label'] ?? ''));

    if ($serverKey === '' || $label === '') fail(400, 'server_key and label are required');
    validate_server_key($serverKey);
    if (mb_strlen($label) > 128) fail(400, 'label too long (max 128)');

    $stmt = $pdo->prepare("UPDATE servers SET label = ? WHERE `key` = ? LIMIT 1");
    $stmt->execute([$label, $serverKey]);

    ok(['updated' => $stmt->rowCount()]);
  }

  fail(404, 'Unknown endpoint');
} catch (Throwable $e) {
  if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) {
    $pdo->rollBack();
  }
  fail(500, 'Server error', $e->getMessage());
}