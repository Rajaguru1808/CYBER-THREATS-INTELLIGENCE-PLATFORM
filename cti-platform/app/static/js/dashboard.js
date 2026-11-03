/* Dashboard charts, powered by Chart.js. Data is injected as global consts
   (severityData, iocTypeData, statusData) by dashboard.html before this
   script loads. */

const SEVERITY_COLORS = {
    critical: '#dc3545', high: '#fd7e14', medium: '#ffc107', low: '#28a745'
};
const TYPE_COLORS = ['#2563eb', '#7c3aed', '#0891b2', '#d97706', '#dc2626', '#16a34a', '#4b5563'];
const STATUS_COLORS = { initial: '#94a3b8', ongoing: '#2563eb', completed: '#28a745' };

function buildDoughnut(canvasId, dataObj, colorMap, fallbackColors, onSliceClick) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const labels = Object.keys(dataObj);
    const values = Object.values(dataObj);
    const colors = labels.map((l, i) => (colorMap && colorMap[l]) || fallbackColors[i % fallbackColors.length]);

    if (labels.length === 0) {
        ctx.parentElement.insertAdjacentHTML('beforeend', '<p class="text-muted text-center mt-4">No data yet</p>');
        return;
    }

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.map(l => l.replace('_', ' ').toUpperCase()),
            datasets: [{ data: values, backgroundColor: colors, borderWidth: 2, borderColor: '#fff' }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            // Clicking a slice (or its legend entry) drills into the matching
            // filtered list instead of just showing a hover tooltip.
            onClick: onSliceClick ? (evt, elements) => {
                if (!elements.length) return;
                onSliceClick(labels[elements[0].index]);
            } : undefined,
            onHover: onSliceClick ? (evt, elements) => {
                evt.native.target.style.cursor = elements.length ? 'pointer' : 'default';
            } : undefined,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { boxWidth: 12, font: { size: 11 } },
                    // The legend has its own click handler by default (it just
                    // toggles the slice on/off). Override it so clicking a
                    // legend entry navigates the same way clicking the slice does.
                    onClick: onSliceClick ? (evt, legendItem) => {
                        onSliceClick(labels[legendItem.index]);
                    } : undefined,
                    onHover: onSliceClick ? (evt) => {
                        evt.native.target.style.cursor = 'pointer';
                    } : undefined,
                    onLeave: onSliceClick ? (evt) => {
                        evt.native.target.style.cursor = 'default';
                    } : undefined
                }
            }
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    buildDoughnut('severityChart', severityData, SEVERITY_COLORS, TYPE_COLORS,
        (severity) => { window.location.href = `/iocs?severity=${severity}`; });
    buildDoughnut('iocTypeChart', iocTypeData, null, TYPE_COLORS,
        (type) => { window.location.href = `/iocs?type=${type}`; });
    buildDoughnut('statusChart', statusData, STATUS_COLORS, TYPE_COLORS,
        (status) => { window.location.href = `/events?status=${status}`; });
});
