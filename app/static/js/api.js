// Handles all network requests to your Flask backend

export async function verifyConnection() {
    try {
        const res = await fetch('/github/profile');
        const path = window.location.pathname;

        // Redirect logic: If on /audit but NOT authorized, kick back to /profile
        if (!res.ok && path === '/audit') {
            window.location.href = '/profile';
        }
        // If on /profile but ALREADY authorized, go straight to /audit
        if (res.ok && path === '/profile') {
            window.location.href = '/audit';
        }
    } catch (error) {
        console.error("Auth check error:", error);
    }
}

export async function fetchAuditReport(repoName) {
    const res = await fetch(`/audit/${repoName}`);
    if (!res.ok) throw new Error("Audit failed");
    return await res.json();
}
