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
      voucherDiv.innerHTML = `
        <div class="error-section">
          <h2 style="margin-top:0">No se encontró información del pedido</h2>
          <p>Intenté buscar por:</p>
          <ul style="margin: 10px 0; padding-left: 20px;">
            <li><strong>Pedido ID:</strong> ${pedidoId || 'no disponible'}</li>
            <li><strong>Sesión ID:</strong> ${sid || 'no disponible'}</li>
            <li><strong>Cliente:</strong> ${cliente || 'no disponible'}</li>
          </ul>
          <p style="margin-bottom:0;"><strong>Sugerencias:</strong></p>
          <ul style="margin: 10px 0; padding-left: 20px;">
            <li>Si acabas de pagar con Stripe, espera 5-10 segundos</li>
            <li>Intenta recargar la página (F5)</li>
            <li>Si el problema persiste, contacta al soporte</li>
          </ul>
        </div>
      `;
      console.warn('[voucher] pedido no encontrado. params:', { pedidoId, sessionId: sid, cliente });
      return;
    }

    // Generar HTML del voucher con estilos empresariales
    let itemsHtml = pedido.items.map(it => `
      <div class="item-row">
        <span><span class="item-qty">${it.cantidad}x</span> ${it.nombre}</span>
        <span class="item-price">$${it.precio * it.cantidad}</span>
      </div>
    `).join('');

    const fechaFormato = new Date(pedido.fecha).toLocaleDateString('es-CL', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });

    const statusClass = pedido.estado && String(pedido.estado).toLowerCase().includes('listo') ? '' : 'pending';
    const statusText = pedido.estado || 'Pendiente';
    const statusIcon = statusClass === 'pending' ? '⏳' : '✓';

    voucherDiv.innerHTML = `
      <div class="voucher-section">
        <h2 class="voucher-title">📋 Detalle del Pedido</h2>
        
        <div class="voucher-info">
          <div class="voucher-field">
            <div class="voucher-label">🔢 Número de Pedido</div>
            <div class="voucher-value">#${pedido.id || 'n/a'}</div>
          </div>
          <div class="voucher-field">
            <div class="voucher-label">📅 Fecha y Hora</div>
            <div class="voucher-value">${fechaFormato}</div>
          </div>
          <div class="voucher-field">
            <div class="voucher-label">👤 Cliente</div>
            <div class="voucher-value">${pedido.cliente}</div>
          </div>
          <div class="voucher-field">
            <div class="voucher-label">✉️ Correo</div>
            <div class="voucher-value">${pedido.email}</div>
          </div>
        </div>

        <!-- Items pedidos -->
        <div class="voucher-items">
          <div class="items-title">🛒 Artículos Pedidos</div>
          ${itemsHtml}
        </div>

        <!-- Total -->
        <div class="total-row">
          <span>💰 Total Pagado:</span>
          <span>$${pedido.total}</span>
        </div>

        <!-- Estado del pedido -->
        <div class="status-section ${statusClass}">
          <span style="font-size: 1.4rem; margin-right: 10px;">${statusIcon}</span>
          <strong>Estado: ${statusText}</strong>
        </div>

        ${pedido.nota ? `<p style="text-align: left; color: #666; font-size: 0.9rem; margin-top: 15px; padding: 12px; background: #f9f9f9; border-left: 3px solid #ffc107; border-radius: 4px;"><strong>📝 Notas:</strong> ${pedido.nota}</p>` : ''}
      </div>
    `;

    // Limpia el localStorage para evitar mostrar el mismo voucher en el futuro
    try { localStorage.removeItem('ultimoCliente'); } catch (e) { /* ignore */ }
    try { localStorage.removeItem('cart'); } catch (e) { /* ignore */ }
    // --- Polling para notificaciones en el navegador del cliente ---
    (function watchPedido(p) {
      const id = p.id;
      let seenListo = p.estado && String(p.estado).toLowerCase().includes('listo');

      async function check() {
        try {
          const r = await fetch('/api/pedidos/' + encodeURIComponent(id));
          if (!r.ok) return;
          const remote = await r.json();
          const estado = remote && remote.estado ? String(remote.estado) : '';
          if (!seenListo && estado.toLowerCase().includes('listo')) {
            seenListo = true;
            // show browser notification if permission
            if (window.Notification) {
              if (Notification.permission === 'granted') {
                new Notification('Pedido listo', { body: `Tu pedido #${id} está listo para retiro.` });
              } else if (Notification.permission === 'default') {
                Notification.requestPermission().then(perm => {
                  if (perm === 'granted') new Notification('Pedido listo', { body: `Tu pedido #${id} está listo para retiro.` });
                }).catch(()=>{});
              }
            }
            // also display inline message
            try{
              const v = document.getElementById('voucher');
              if (v) {
                const el = document.createElement('div');
                el.className = 'notification-banner status-section';
                el.style.padding = '15px';
                el.style.borderRadius = '8px';
                el.style.marginTop = '12px';
                el.style.background = '#d1e7dd';
                el.style.color = '#0f5132';
                el.style.fontWeight = 'bold';
                el.style.animation = 'slideDown 0.5s ease-out';
                el.innerText = `✓ Tu pedido #${id} está listo para retiro.`;
                v.prepend(el);
              }
            }catch(e){}
          }
        } catch (e) { /* ignore transient errors */ }
      }

      // Start periodic checks (5s) while page open
      const timer = setInterval(check, 5000);
      // initial delayed check
      setTimeout(check, 1500);
      // stop when user navigates away
      window.addEventListener('beforeunload', ()=> clearInterval(timer));
    })(pedido);
  } catch (e) {
    voucherDiv.innerHTML = '<p>Error al cargar el voucher.</p>';
  }
});
