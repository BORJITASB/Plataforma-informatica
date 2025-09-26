<?php

session_start();
if (!isset($_SESSION['id_usuario']) || $_SESSION['rol'] !== 'admin') {
    header('Location: ../views/login.php');
    exit;
}
require_once("../config/config.php");

// Detectar si existe columna imagen en la tabla productos (modo tolerante)
$hasImagen = false;
try { $pdo->query("SELECT imagen FROM productos LIMIT 1"); $hasImagen = true; } catch(Exception $e) { $hasImagen = false; }

// Preparar carpeta de subida si se maneja imagen
if ($hasImagen) {
    $uploadDir = realpath(__DIR__ . '/../assets/img');
    if ($uploadDir && is_dir($uploadDir)) {
        $uploadSubDir = $uploadDir . DIRECTORY_SEPARATOR . 'productos';
        if (!is_dir($uploadSubDir)) @mkdir($uploadSubDir, 0775, true);
    } else {
        $hasImagen = false; // Fallback si ruta base no existe
    }
}

function manejarSubidaImagen($campo, $hasImagen) {
    if (!$hasImagen || empty($_FILES[$campo]) || ($_FILES[$campo]['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return null; // No se subió imagen
    }
    $file = $_FILES[$campo];
    if ($file['error'] !== UPLOAD_ERR_OK) return null;
    // Validar tamaño (<= 2MB)
    if ($file['size'] > 2 * 1024 * 1024) return null;
    // Validar extensión
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $permitidas = ['jpg','jpeg','png','webp','gif'];
    if (!in_array($ext, $permitidas)) return null;
    // Nombre seguro
    $base = preg_replace('/[^a-zA-Z0-9_-]/','', pathinfo($file['name'], PATHINFO_FILENAME));
    if ($base === '') $base = 'img';
    $nombreFinal = $base . '_' . date('Ymd_His') . '_' . bin2hex(random_bytes(3)) . '.' . $ext;
    $dest = realpath(__DIR__ . '/../assets/img') . DIRECTORY_SEPARATOR . 'productos' . DIRECTORY_SEPARATOR . $nombreFinal;
    if (@move_uploaded_file($file['tmp_name'], $dest)) {
        return 'productos/' . $nombreFinal; // Ruta relativa desde assets/img
    }
    return null;
}

// Agregar producto
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['accion'] ?? '') === 'agregar') {
    // Verificación CSRF
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        header('Location: ../views/productos_admin.php?mensaje=Token+inválido&tipo=danger');
        exit;
    }
    $nombre = trim($_POST['nombre']);
    $descripcion = trim($_POST['descripcion']);
    $id_categoria = intval($_POST['id_categoria']);
    $imagen = manejarSubidaImagen('imagen', $hasImagen);
    if ($hasImagen) {
        $stmt = $pdo->prepare("INSERT INTO productos (nombre, descripcion, id_categoria, imagen) VALUES (?,?,?,?)");
        $stmt->execute([$nombre, $descripcion, $id_categoria, $imagen]);
    } else {
        $stmt = $pdo->prepare("INSERT INTO productos (nombre, descripcion, id_categoria) VALUES (?, ?, ?)");
        $stmt->execute([$nombre, $descripcion, $id_categoria]);
    }
    header('Location: ../views/productos_admin.php');
    exit;
}

// Agregar categoría (soporta AJAX JSON)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['accion'] ?? '') === 'agregar_categoria') {
    $isAjax = (
        (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest')
        || (isset($_POST['ajax']) && $_POST['ajax'] === '1')
        || (isset($_SERVER['HTTP_ACCEPT']) && str_contains($_SERVER['HTTP_ACCEPT'], 'application/json'))
    );
    $respond = function(array $payload, bool $ajax) {
        if ($ajax) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($payload, JSON_UNESCAPED_UNICODE);
        } else {
            // Fallback redirect
            $msg = urlencode($payload['message'] ?? '');
            $tipo = urlencode($payload['status'] ?? 'info');
            header("Location: ../views/productos_admin.php?mensaje={$msg}&tipo={$tipo}");
        }
        exit;
    };
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        $respond(['status'=>'danger','message'=>'Token inválido'], $isAjax);
    }
    $nombreCat = trim($_POST['nombre_categoria'] ?? '');
    if ($nombreCat === '') {
        $respond(['status'=>'warning','message'=>'Nombre de categoría requerido'], $isAjax);
    }
    $stmt = $pdo->prepare("SELECT id_categoria FROM categorias WHERE LOWER(nombre)=LOWER(?)");
    $stmt->execute([$nombreCat]);
    if ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $respond(['status'=>'warning','message'=>'La categoría ya existe','id_categoria'=>$row['id_categoria']], $isAjax);
    }
    $stmt = $pdo->prepare("INSERT INTO categorias (nombre) VALUES (?)");
    $stmt->execute([$nombreCat]);
    $newId = $pdo->lastInsertId();
    $respond(['status'=>'success','message'=>'Categoría creada','id_categoria'=>$newId,'nombre'=>$nombreCat], $isAjax);
}

// Editar producto
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['accion'] ?? '') === 'editar') {
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        header('Location: ../views/productos_admin.php?mensaje=Token+inválido&tipo=danger');
        exit;
    }
    $id = intval($_POST['id_producto']);
    $nombre = trim($_POST['nombre']);
    $descripcion = trim($_POST['descripcion']);
    $id_categoria = intval($_POST['id_categoria']);
    $imagenActual = $_POST['imagen_actual'] ?? null;
    $nuevaImagen = manejarSubidaImagen('imagen', $hasImagen);
    if ($hasImagen) {
        if ($nuevaImagen) {
            $stmt = $pdo->prepare("UPDATE productos SET nombre=?, descripcion=?, id_categoria=?, imagen=? WHERE id_producto=?");
            $stmt->execute([$nombre, $descripcion, $id_categoria, $nuevaImagen, $id]);
        } else {
            $stmt = $pdo->prepare("UPDATE productos SET nombre=?, descripcion=?, id_categoria=? WHERE id_producto=?");
            $stmt->execute([$nombre, $descripcion, $id_categoria, $id]);
        }
    } else {
        $stmt = $pdo->prepare("UPDATE productos SET nombre=?, descripcion=?, id_categoria=? WHERE id_producto=?");
        $stmt->execute([$nombre, $descripcion, $id_categoria, $id]);
    }
    header('Location: ../views/productos_admin.php');
    exit;
}

// Eliminar producto (POST seguro)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['accion'] ?? '') === 'eliminar') {
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        header('Location: ../views/productos_admin.php?mensaje=Token+inválido&tipo=danger');
        exit;
    }
    $id = intval($_POST['id_producto'] ?? 0);
    if ($id > 0) {
        $stmt = $pdo->prepare("DELETE FROM productos WHERE id_producto=?");
        $stmt->execute([$id]);
        header('Location: ../views/productos_admin.php?mensaje=Producto+eliminado&tipo=success');
    } else {
        header('Location: ../views/productos_admin.php?mensaje=ID+inválido&tipo=warning');
    }
    exit;
}
?>