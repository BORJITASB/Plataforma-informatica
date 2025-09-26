<?php
// Apertura del script PHP.

session_start(); // Inicia o reanuda la sesión para poder almacenar datos del usuario autenticado.

// Comentario: Se removió un volcado inseguro de la sesión que antes se hacía a un archivo.
header('Content-Type: application/json'); // Indica que todas las respuestas se devolverán en formato JSON.

require_once("../config/config.php"); // Incluye la configuración y la conexión PDO a la base de datos.

$input = json_decode(file_get_contents('php://input'), true); // Lee el cuerpo crudo de la petición (JSON) y lo convierte a array asociativo.

if (empty($input['correo']) || empty($input['contrasena'])) { // Verifica que los campos necesarios no estén vacíos.
    echo json_encode(['status' => 'error', 'message' => 'Todos los campos son obligatorios.']); // Responde con error si falta algún dato.
    exit; // Detiene la ejecución del script.
}

$correo = trim($input['correo']); // Normaliza el correo eliminando espacios en blanco al inicio y final.
$contrasena = $input['contrasena']; // Obtiene la contraseña tal cual llega (se verificará con hash luego).

$stmt = $pdo->prepare("SELECT id_usuario, nombre, correo, contraseña, rol FROM usuarios WHERE correo = ?"); // Prepara consulta segura para buscar usuario por correo.
$stmt->execute([$correo]); // Ejecuta consulta pasando el correo como parámetro (previene inyección SQL).
$usuario = $stmt->fetch(PDO::FETCH_ASSOC); // Recupera el registro del usuario como array asociativo o false si no existe.

if ($usuario && password_verify($contrasena, $usuario['contraseña'])) { // Comprueba que el usuario exista y que el hash de la contraseña coincida.
    $_SESSION['id_usuario'] = $usuario['id_usuario']; // Guarda el id del usuario en la sesión.
    $_SESSION['nombre'] = $usuario['nombre']; // Guarda el nombre para mostrarlo en el dashboard.
    $_SESSION['rol'] = $usuario['rol']; // Guarda el rol (admin/usuario) para controles de acceso.
    echo json_encode(['status' => 'ok', 'rol' => $usuario['rol']]); // Responde con estado exitoso y el rol.
} else { // Si no coincide la contraseña o no existe el usuario...
    echo json_encode(['status' => 'error', 'message' => 'Correo o contraseña incorrectos.']); // Devuelve error genérico.
}

// Cierre del script.
?>
