<?php
session_start();
if (!isset($_SESSION['id_usuario']) || ($_SESSION['rol'] ?? '') !== 'admin') {
    header('Location: login.php');
    exit;
}
require_once("../config/config.php");
// Métricas básicas
try { $totProductos = (int)$pdo->query("SELECT COUNT(*) FROM productos")->fetchColumn(); } catch(Exception $e) { $totProductos = 0; }
try { $totCategorias = (int)$pdo->query("SELECT COUNT(*) FROM categorias")->fetchColumn(); } catch(Exception $e) { $totCategorias = 0; }
try { $totUsuarios = (int)$pdo->query("SELECT COUNT(*) FROM usuarios")->fetchColumn(); } catch(Exception $e) { $totUsuarios = 0; }
// Últimos productos
$lastProductos = [];
try { $stmtLast = $pdo->query("SELECT id_producto, nombre, descripcion FROM productos ORDER BY id_producto DESC LIMIT 5"); $lastProductos = $stmtLast->fetchAll(PDO::FETCH_ASSOC);} catch(Exception $e) {}
// Últimos usuarios
$lastUsuarios = [];
try { $stmtUsers = $pdo->query("SELECT id_usuario, nombre, correo FROM usuarios ORDER BY id_usuario DESC LIMIT 5"); $lastUsuarios = $stmtUsers->fetchAll(PDO::FETCH_ASSOC);} catch(Exception $e) {}
// Top categorías
$catsData = [];
try { $stmtCats = $pdo->query("SELECT c.nombre AS categoria, COUNT(p.id_producto) total FROM categorias c LEFT JOIN productos p ON p.id_categoria = c.id_categoria GROUP BY c.id_categoria, c.nombre ORDER BY total DESC LIMIT 6"); $catsData = $stmtCats->fetchAll(PDO::FETCH_ASSOC);} catch(Exception $e) {}
$chartLabels = array_map(fn($r) => $r['categoria'], $catsData);
$chartValues = array_map(fn($r) => (int)$r['total'], $catsData);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Dashboard | Admin</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="../assets/css/dashboard.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
</head>
<body class="dashboard-body">
    <div class="dashboard-overlay"></div>
    <div class="layout-wrapper">
        <div class="sidebar" id="sidebar">
            <div class="brand">⚙️ Admin</div>
            <nav class="flex-grow-1">
                <a class="nav-link active" href="admin_dashboard.php">Dashboard</a>
                <a class="nav-link" href="productos_admin.php">Productos</a>
                <a class="nav-link" href="catalogo.php" target="_blank">Ver Catálogo</a>
                <a class="nav-link" href="solicitudes.php">Solicitudes (próx.)</a>
            </nav>
            <div class="logout">
                <a class="nav-link" href="../controllers/logout.php">⏻ Cerrar sesión</a>
            </div>
        </div>
        <div class="main-content">
            <button class="mobile-toggle d-md-none" id="btnToggle">☰</button>
            <h1 class="page-title">Hola, <?= htmlspecialchars($_SESSION['nombre'] ?? 'Administrador') ?> <span class="badge badge-soft">Panel</span></h1>
            <section class="stat-cards">
                <div class="stat-card"><h6>Productos</h6><div class="stat-value"><?= $totProductos ?></div><div class="stat-trend">Total registrados</div></div>
                <div class="stat-card"><h6>Categorías</h6><div class="stat-value"><?= $totCategorias ?></div><div class="stat-trend">Activas</div></div>
                <div class="stat-card"><h6>Usuarios</h6><div class="stat-value"><?= $totUsuarios ?></div><div class="stat-trend">Registrados</div></div>
                <div class="stat-card"><h6>Ratio Prod/Cat</h6><div class="stat-value"><?= $totCategorias ? round($totProductos / max($totCategorias,1),1) : 0 ?></div><div class="stat-trend">Promedio por categoría</div></div>
            </section>
            <div class="row g-4">
                <div class="col-lg-7">
                    <div class="panel">
                        <div class="panel-header d-flex justify-content-between align-items-center mb-2"><h5 class="m-0">Top Categorías</h5></div>
                        <div class="chart-wrapper"><canvas id="catChart" aria-label="Gráfico de categorías" role="img"></canvas></div>
                    </div>
                </div>
                <div class="col-lg-5">
                    <div class="panel">
                        <div class="panel-header d-flex justify-content-between align-items-center mb-2"><h5 class="m-0">Últimos Productos</h5><a href="productos_admin.php" class="btn btn-sm btn-outline-light">Gestionar</a></div>
                        <?php if ($lastProductos): ?>
                        <div class="table-responsive small">
                            <table class="table table-dark-glass align-middle mb-0 table-sm last-products-table">
                                <thead><tr><th>Nombre</th><th style="width:55%">Descripción</th></tr></thead>
                                <tbody>
                                <?php foreach($lastProductos as $p): ?>
                                    <tr><td><?= htmlspecialchars($p['nombre']) ?></td><td><?= htmlspecialchars(mb_strimwidth($p['descripcion'] ?? '',0,55,'…')) ?></td></tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php else: ?><p class="text-muted mb-0">Sin productos aún.</p><?php endif; ?>
                    </div>
                </div>
            </div>
            <div class="row g-4">
                <div class="col-lg-6">
                    <div class="panel">
                        <div class="panel-header mb-2"><h5 class="m-0">Últimos Usuarios</h5></div>
                        <?php if ($lastUsuarios): ?>
                        <div class="table-responsive small">
                            <table class="table table-dark-glass align-middle mb-0 table-sm"><thead><tr><th>Nombre</th><th>Correo</th></tr></thead><tbody>
                            <?php foreach($lastUsuarios as $u): ?><tr><td><?= htmlspecialchars($u['nombre']) ?></td><td><?= htmlspecialchars($u['correo']) ?></td></tr><?php endforeach; ?>
                            </tbody></table>
                        </div>
                        <?php else: ?><p class="text-muted mb-0">Sin usuarios registrados.</p><?php endif; ?>
                    </div>
                </div>
                <div class="col-lg-6">
                    <div class="panel">
                        <div class="panel-header mb-2"><h5 class="m-0">Acciones Rápidas</h5></div>
                        <div class="d-grid gap-2">
                            <a href="productos_admin.php" class="btn btn-outline-light btn-sm">➕ Nuevo Producto</a>
                            <a href="productos_admin.php" class="btn btn-outline-light btn-sm">🗂 Gestionar Productos</a>
                            <a href="catalogo.php" target="_blank" class="btn btn-outline-light btn-sm">🛒 Ver Catálogo Público</a>
                            <button class="btn btn-outline-light btn-sm" disabled>📄 Solicitudes (próximamente)</button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="footer-mini">&copy; <?= date('Y') ?> Compra Tecnológica · Panel Administrador</div>
        </div>
    </div>
    <script>
        const btnToggle = document.getElementById('btnToggle');
        const sidebar = document.getElementById('sidebar');
        if (btnToggle) { btnToggle.addEventListener('click', () => sidebar.classList.toggle('open')); }
        const labels = <?= json_encode($chartLabels, JSON_UNESCAPED_UNICODE) ?>;
        const dataVals = <?= json_encode($chartValues) ?>;
        if (labels.length) {
            new Chart(document.getElementById('catChart'), { type: 'bar', data: { labels, datasets: [{ label: 'Productos', data: dataVals, backgroundColor: ['#4dabf7','#748ffc','#9775fa','#e599f7','#ffa8a8','#ff8787'], borderRadius: 6 }]}, options: { plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#e2e8f0', font:{ size: 11 } }, grid: { display:false } }, y: { ticks: { color: '#b5bcc4', font:{ size: 11 } }, grid: { color: 'rgba(255,255,255,0.08)' }, beginAtZero:true } } } });
        } else {
            const c = document.getElementById('catChart'); if (c) { const ctx = c.getContext('2d'); ctx.fillStyle = '#ccc'; ctx.font = '14px Segoe UI'; ctx.fillText('Sin datos de categorías', 20, 40); }
        }
    </script>
</body>
</html>