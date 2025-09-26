<?php

header('Content-Type: application/json');
require_once("../config/config.php");

$input = json_decode(file_get_contents('php://input'), true);

if (
    empty($input['nombre']) ||
    empty($input['correo']) ||
    empty($input['contrasena'])
) {
    echo json_encode(['status' => 'error', 'message' => 'Todos los campos son obligatorios.']);
    exit;
}

$nombre = trim($input['nombre']);
$correo = trim($input['correo']);
$contrasena = $input['contrasena'];

// Validar correo
if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['status' => 'error', 'message' => 'Correo no válido.']);
    exit;
}

// Verificar si el correo ya existe
$stmt = $pdo->prepare("SELECT id_usuario FROM usuarios WHERE correo = ?");
$stmt->execute([$correo]);
if ($stmt->fetch()) {
    echo json_encode(['status' => 'error', 'message' => 'El correo ya está registrado.']);
    exit;
}

// Hashear contraseña
$hash = password_hash($contrasena, PASSWORD_DEFAULT);

$stmt = $pdo->prepare("INSERT INTO usuarios (nombre, correo, contraseña, rol) VALUES (?, ?, ?, 'usuario')");
if ($stmt->execute([$nombre, $correo, $hash])) {
    echo json_encode(['status' => 'ok', 'message' => 'Usuario registrado correctamente.']);
} else {
    echo json_encode(['status' => 'error', 'message' => 'Error al registrar usuario.']);
}
?>