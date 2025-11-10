// Script para success.html: muestra el voucher del último pedido
window.addEventListener('DOMContentLoaded', async () => {
  const voucherDiv = document.getElementById('voucher');
  const params = new URLSearchParams(window.location.search);
  const sessionId = params.get('session_id');
  const pedidoId = params.get('pedidoId');
  const cliente = localStorage.getItem('ultimoCliente');
  try {
    let pedido = null;
    // Si viene pedidoId en la URL, pedirlo directamente
    if (pedidoId) {
      const res = await fetch('/api/pedidos/' + encodeURIComponent(pedidoId));
      console.log('[voucher] buscando por pedidoId', pedidoId, ' status=', res.status);
      if (res.ok) pedido = await res.json();
    }
    // Intentar por sessionId (varios nombres posibles)
    const sid = sessionId || params.get('sessionId') || params.get('checkout_session');
    if (!pedido && sid) {
      try {
        const res = await fetch('/api/pedidos?sessionId=' + encodeURIComponent(sid));
        console.log('[voucher] buscando por sessionId', sid, ' status=', res.status);
        const pedidos = await res.json();
        if (Array.isArray(pedidos) && pedidos.length) pedido = pedidos[0];
      } catch (e) { console.warn('[voucher] error buscando por sessionId', e); }
    }

    // Si no hay pedido aún, intentar buscar por cliente (case-insensitive) o por email
    if (!pedido && cliente) {
      try {
        const res = await fetch('/api/pedidos');
        console.log('[voucher] buscando por cliente localStorage', cliente, ' status=', res.status);
        const pedidos = await res.json();
        const lc = (cliente || '').toLowerCase().trim();
        const pedidosCliente = pedidos.filter(p => (p.cliente || '').toLowerCase().trim() === lc || (p.email || '').toLowerCase().trim() === lc);
        if (pedidosCliente.length) {
          pedido = pedidosCliente.sort((a, b) => new Date(b.fecha) - new Date(a.fecha))[0];
        } else {
          // fuzzy search: contains
          const encontrados = pedidos.filter(p => (p.cliente || '').toLowerCase().includes(lc) || (p.email || '').toLowerCase().includes(lc));
          if (encontrados.length) pedido = encontrados.sort((a, b) => new Date(b.fecha) - new Date(a.fecha))[0];
        }
      } catch (e) { console.warn('[voucher] error buscando pedidos generales', e); }
    }
    if (!pedido) {
      // Mostrar mensaje más útil y log de diagnóstico
      voucherDiv.innerHTML = `<div class="cont-formulario" style="max-width:400px;margin:0 auto;"><h2 class="titulo2">No se encontró información del pedido</h2><p>Intenté buscar por:</p><ul><li>pedidoId: ${pedidoId || 'n/a'}</li><li>sessionId: ${sid || 'n/a'}</li><li>cliente(localStorage): ${cliente || 'n/a'}</li></ul><p>Si acabas de pagar con Stripe, espera unos segundos o revisa la consola del servidor (webhook). Si el problema persiste, pega aquí los logs de la consola del navegador y del servidor.</p></div>`;
      console.warn('[voucher] pedido no encontrado. params:', { pedidoId, sessionId: sid, cliente });
      return;
    }
    let itemsHtml = pedido.items.map(it => `<li>${it.cantidad} x ${it.nombre} - $${it.precio * it.cantidad}</li>`).join('');
    voucherDiv.innerHTML = `
      <div class="cont-formulario" style="max-width:400px;margin:0 auto;">
        <h2 class="titulo2">Voucher de Pago</h2>
        <p><strong>Pedido #:</strong> ${pedido.id || 'n/a'}</p>
        <p><strong>Cliente:</strong> ${pedido.cliente}</p>
        <p><strong>Fecha:</strong> ${new Date(pedido.fecha).toLocaleString()}</p>
        <ul style="text-align:left;">${itemsHtml}</ul>
        <p><strong>Total pagado:</strong> $${pedido.total}</p>
        <p style="color:#18944c;font-weight:bold;">Estado: ${pedido.estado}</p>
      </div>
    `;
    // Limpia el localStorage para evitar mostrar el mismo voucher en el futuro y vaciar el carrito
    try { localStorage.removeItem('ultimoCliente'); } catch (e) { /* ignore */ }
    try { localStorage.removeItem('cart'); } catch (e) { /* ignore */ }
  } catch (e) {
    voucherDiv.innerHTML = '<p>Error al cargar el voucher.</p>';
  }
});
