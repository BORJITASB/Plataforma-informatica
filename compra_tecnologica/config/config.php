<?php
// Carga de variables de entorno (.env) sencilla sin dependencias externas.
// Formato esperado: CLAVE=valor (comentarios con # al inicio de línea)
$envPath = __DIR__ . '/../.env';
if (is_readable($envPath)) {
    $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (str_starts_with(trim($line), '#')) continue; // Comentario
        if (!str_contains($line, '=')) continue; // Línea inválida
        [$k,$v] = array_map('trim', explode('=',$line,2));
        if ($k !== '' && !array_key_exists($k, $_ENV)) {
            $_ENV[$k] = $v;
            putenv("$k=$v");
        }
    }
}

// Helper para obtener variables con fallback
function envv(string $key, $default = null) {
    $val = $_ENV[$key] ?? getenv($key);
    return ($val === false || $val === null || $val === '') ? $default : $val;
}

$DB_HOST = envv('DB_HOST', 'localhost');
$DB_PORT = (int) envv('DB_PORT', 3307);
$DB_NAME = envv('DB_NAME', 'compras_tecnologicas');
$DB_USER = envv('DB_USER', 'root');
$DB_PASS = envv('DB_PASS', '');

// Conexión mysqli (si aún se usa en alguna parte legacy)
$conn = @new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME, $DB_PORT);
if ($conn->connect_errno) {
    // No detener la app si falla; se usará PDO más abajo (log básico)
    error_log('MySQLi connection failed: ' . $conn->connect_error);
}

// Conexión PDO principal
try {
    $pdo = new PDO(
        "mysql:host={$DB_HOST};dbname={$DB_NAME};port={$DB_PORT};charset=utf8mb4",
        $DB_USER,
        $DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
} catch (PDOException $e) {
    if (envv('APP_DEBUG', 'false') === 'true') {
        die('Error de conexión PDO: ' . $e->getMessage());
    }
    // Mensaje genérico en producción
    die('Error interno de base de datos.');
}
?>
