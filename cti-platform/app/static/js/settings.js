/* Settings page: "Test Connection" buttons call the API config test endpoint
   via fetch() and update the status badge without a full page reload. */
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.test-connection-btn').forEach((btn) => {
        btn.addEventListener('click', async () => {
            const service = btn.dataset.service;
            const badge = document.getElementById(`status-badge-${service}`);
            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Testing...';

            try {
                const resp = await fetch(`/settings/api/${service}/test`, { method: 'POST' });
                const data = await resp.json();

                if (badge) {
                    badge.textContent = data.status ? data.status[0].toUpperCase() + data.status.slice(1) : 'Unknown';
                    badge.className = 'badge ' + (data.success ? 'bg-success' : 'bg-danger');
                }
                alert(data.success ? `${service.toUpperCase()}: Connected successfully!`
                                    : `${service.toUpperCase()}: Connection failed - ${data.message}`);
            } catch (err) {
                alert(`Test failed: ${err}`);
            } finally {
                btn.disabled = false;
                btn.textContent = originalText;
            }
        });
    });
});
