<?php
// Script: registro.php (controlador para registrar productos vía AJAX JSON)
// Respuesta en JSON para integrarse con fetch en el frontend.

header('Content-Type: application/json'); // Fija cabecera HTTP a JSON.

require_once("../config/config.php"); // Incluye conexión PDO a la base de datos.

$input = json_decode(file_get_contents('php://input'), true); // Decodifica el cuerpo JSON a array asociativo.

// Validación de campos obligatorios.
if (
    empty($input['nombre']) ||
    empty($input['descripcion']) ||
    empty($input['id_categoria'])
) {
    echo json_encode(['status' => 'error', 'message' => 'Todos los campos son obligatorios.']); // Respuesta de error.
    exit; // Termina ejecución.
}

// Limpieza y tipado.
$nombre = trim($input['nombre']); // Limpia espacios.
$descripcion = trim($input['descripcion']); // Limpia espacios.
$id_categoria = intval($input['id_categoria']); // Convierte a entero.

try {
    $stmt = $pdo->prepare("INSERT INTO productos (nombre, descripcion, id_categoria) VALUES (?, ?, ?)"); // Sentencia preparada.
    $stmt->execute([$nombre, $descripcion, $id_categoria]); // Ejecuta con parámetros.
    echo json_encode(['status' => 'ok', 'message' => 'Producto registrado correctamente.']); // Éxito.
} catch (Exception $e) {
    echo json_encode(['status' => 'error', 'message' => 'Error al registrar el producto.']); // Error genérico.
}
?>
