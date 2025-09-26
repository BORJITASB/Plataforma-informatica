<?php

session_start();

// Eliminado volcado inseguro de la sesión a un archivo debug.
header('Content-Type: application/json');

require_once("../config/config.php");

$input = json_decode(file_get_contents('php://input'), true);

if (empty($input['correo']) || empty($input['contrasena'])) {
    echo json_encode(['status' => 'error', 'message' => 'Todos los campos son obligatorios.']);
    exit;
}

$correo = trim($input['correo']);
$contrasena = $input['contrasena'];

$stmt = $pdo->prepare("SELECT id_usuario, nombre, correo, contraseña, rol FROM usuarios WHERE correo = ?");
$stmt->execute([$correo]);
$usuario = $stmt->fetch(PDO::FETCH_ASSOC);

if ($usuario && password_verify($contrasena, $usuario['contraseña'])) {
    $_SESSION['id_usuario'] = $usuario['id_usuario'];
    $_SESSION['nombre'] = $usuario['nombre'];
    $_SESSION['rol'] = $usuario['rol'];
    echo json_encode(['status' => 'ok', 'rol' => $usuario['rol']]);
} else {
    echo json_encode(['status' => 'error', 'message' => 'Correo o contraseña incorrectos.']);
}
?>
