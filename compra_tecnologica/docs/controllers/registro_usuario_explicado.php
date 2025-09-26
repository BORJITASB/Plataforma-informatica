<?php
// Script: registro_usuario.php (controlador de alta de usuarios vía AJAX JSON)
// Crea un nuevo usuario con rol 'usuario' validando email único y contraseñas.

header('Content-Type: application/json'); // Salida en JSON.
require_once("../config/config.php"); // Conexión PDO.

$input = json_decode(file_get_contents('php://input'), true); // Decodifica JSON recibido.

// Validar presencia de campos.
if (
    empty($input['correo']) ||
    empty($input['nombre']) ||
    empty($input['password']) ||
    empty($input['confirm_password'])
) {
    echo json_encode(['status' => 'error', 'message' => 'Todos los campos son obligatorios.']);
    exit;
}

$correo = trim($input['correo']); // Normaliza email.
$nombre = trim($input['nombre']); // Normaliza nombre.
$password = $input['password']; // Password en texto plano (temporalmente).
$confirm_password = $input['confirm_password']; // Confirmación.

// Verifica coincidencia de contraseñas.
if ($password !== $confirm_password) {
    echo json_encode(['status' => 'error', 'message' => 'Las contraseñas no coinciden.']);
    exit;
}

try {
    // Comprueba si el correo ya existe.
    $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE correo = ? LIMIT 1");
    $stmt->execute([$correo]);
    if ($stmt->fetch()) { // Si encuentra registro.
        echo json_encode(['status' => 'error', 'message' => 'El correo ya está registrado.']);
        exit;
    }

    // Hashea la contraseña usando algoritmo por defecto (bcrypt).
    $hash = password_hash($password, PASSWORD_DEFAULT);

    // Inserta nuevo usuario con rol 'usuario'.
    $stmt = $pdo->prepare("INSERT INTO usuarios (correo, nombre, password, rol) VALUES (?, ?, ?, 'usuario')");
    $stmt->execute([$correo, $nombre, $hash]);

    echo json_encode(['status' => 'ok', 'message' => 'Usuario registrado correctamente.']);
} catch (Exception $e) {
    echo json_encode(['status' => 'error', 'message' => 'Error al registrar el usuario.']); // No exponer detalles sensibles.
}
?>
