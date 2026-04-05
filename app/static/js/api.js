// Handles all network requests to your Flask backend

export async function verifyConnection() {
    try {
        const res = await fetch('/github/profile');
        if (res.status === 401 || res.status === 400) {
            document.getElementById('connection-panel').style.display = 'block';
            return;
        }
        console.log("[DEBUG] Connection verified with backend. Status:", res);
        document.getElementById('connection-panel').style.display = 'none';
        document.getElementById('input-panel').style.display = 'block';
    } catch (error) {
        console.error("Auth check error:", error);
    }
}

export async function fetchAuditReport(repoName) {
    const res = await fetch(`/audit/${repoName}`);
    if (!res.ok) throw new Error("Audit failed");
    return await res.json();
}
