<?php
// Indica que la respuesta será en formato JSON
header('Content-Type: application/json');

// Incluye el archivo de configuración para la conexión a la base de datos
require_once("../config/config.php");

// Lee el cuerpo de la petición (espera JSON) y lo convierte en un array asociativo de PHP
$input = json_decode(file_get_contents('php://input'), true);

// --- VALIDACIÓN DE CAMPOS ---
// Verifica que los campos requeridos no estén vacíos
if (
    empty($input['nombre']) ||
    empty($input['descripcion']) ||
    empty($input['id_categoria'])
) {
    // Si falta algún campo, responde con error y termina la ejecución
    echo json_encode(['status' => 'error', 'message' => 'Todos los campos son obligatorios.']);
    exit;
}

// --- ASIGNACIÓN Y LIMPIEZA DE VARIABLES ---
// Limpia y asigna los valores recibidos
$nombre = trim($input['nombre']);
$descripcion = trim($input['descripcion']);
$id_categoria = intval($input['id_categoria']);

try {
    // Prepara la consulta SQL para insertar el producto usando sentencias preparadas (evita inyección SQL)
    $stmt = $pdo->prepare("INSERT INTO productos (nombre, descripcion, id_categoria) VALUES (?, ?, ?)");
    // Ejecuta la consulta con los valores proporcionados
    $stmt->execute([$nombre, $descripcion, $id_categoria]);
    // Si todo sale bien, responde con éxito
    echo json_encode(['status' => 'ok', 'message' => 'Producto registrado correctamente.']);
} catch (Exception $e) {
    // Si ocurre un error, responde con mensaje de error
    echo json_encode(['status' => 'error', 'message' => 'Error al registrar el producto.']);
}
?>
