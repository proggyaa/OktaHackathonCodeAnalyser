// The entry point that ties them together

import { verifyConnection, fetchAuditReport } from './api.js';
import { render3DGraph, applyGraphFilter, inspectNodeFromCard } from './graph3d.js';
import { populateDashboard, toggleFlip, openScorecard, closeScorecard, openNodeDetails, closeNodeDetails, resetDashboard } from './dashboard.js';

// Make functions global for onclick handlers
window.toggleFlip = toggleFlip;
window.applyGraphFilter = applyGraphFilter;
window.executeAudit = executeAudit;
window.openScorecard = openScorecard;
window.closeScorecard = closeScorecard;
window.inspectNodeFromCard = inspectNodeFromCard;
window.openNodeDetails = openNodeDetails;
window.closeNodeDetails = closeNodeDetails;
window.resetDashboard = resetDashboard;

// Global State
let currentLLMReport = null;
let currentGraphData = null;

async function init() {
    const path = window.location.pathname;
    
    // Don't run any logic on the home/login page
    if (path === '/') return;

    // Run the redirect guard for all other pages
    await verifyConnection();
}

async function executeAudit() {
    const repoName = document.getElementById('repo-input').value.trim();
    
    console.log(`%c[AUDIT START] Target Repo: ${repoName}`, "color: #00ff00; font-weight: bold;");

    if (!repoName) {
        alert("Please enter a repository name.");
        return;
    }

    // UI Reset
    document.querySelectorAll('.is-flipped').forEach(card => card.classList.remove('is-flipped'));
    document.getElementById('input-panel').style.display = 'none';
    document.getElementById('report-panel').style.display = 'block';
    document.getElementById('loading-state').style.display = 'flex';
    document.getElementById('results-state').style.display = 'none';

    try {
        console.log("[STEP 1] Fetching from backend... this might take ~60s.");
        const startTime = performance.now();
        
        const backendData = await fetchAuditReport(repoName);
        const warningBanner = document.getElementById('token-exhaustion-banner');
        if (backendData.error_type === "TOKEN_LIMIT_EXCEEDED") {
            warningBanner.classList.add('active');
        } else {
            warningBanner.classList.remove('active');
        }

        const duration = ((performance.now() - startTime) / 1000).toFixed(2);
        console.log(`[STEP 2] Backend responded in ${duration}s`);
        console.log("[DEBUG] Full Raw Backend Data:", backendData);

        // Check for specific error key in JSON
        if (backendData && backendData.error) {
            console.error("[ERROR] Backend reported logic error:", backendData.details);
            alert("Audit Failed: " + (backendData.details || "Check backend logs"));
            resetDashboard();
            return;
        }

        // UNWRAP LOGIC: Handle the [ { ... } ] array wrap if it exists
        let data = backendData;
        if (Array.isArray(backendData)) {
            console.warn("[WARN] Data received as Array. Unwrapping index 0.");
            data = backendData[0];
        }

        // Data Extraction
        currentLLMReport = data.llm_report;
        currentGraphData = data.graph_data;

        console.log("[STEP 3] CurrentLLMReport assigned:", currentLLMReport);
        console.log("[STEP 4] CurrentGraphData assigned:", currentGraphData);

        // Validation
        if (!currentLLMReport) {
            console.error("[CRITICAL] llm_report is missing from response!");
        }
        if (!currentGraphData || !currentGraphData.nodes) {
            console.error("[CRITICAL] graph_data or graph_data.nodes is missing!");
            console.log("Type of currentGraphData:", typeof currentGraphData);
            alert("Audit returned no visualization data (Graph missing).");
            // We continue anyway to try and show the report
        }

        // Sync to window for other modules
        window.currentGraphData = currentGraphData;
        window.currentLLMReport = currentLLMReport;

        // UI Transition
        console.log("[STEP 5] Transitioning to Results UI...");
        document.getElementById('loading-state').style.display = 'none';
        document.getElementById('results-state').style.display = 'block';

        // Final Render calls
        if (currentLLMReport && currentGraphData?.nodes) {
            console.log("[STEP 6] Populating Dashboard...");
            populateDashboard(currentLLMReport, currentGraphData);
        }

        if (currentGraphData && currentGraphData.nodes.length > 0) {
            console.log(`[STEP 7] Rendering 3D Graph with ${currentGraphData.nodes.length} nodes...`);
            render3DGraph(currentGraphData);
        }

    } catch (error) {
        console.error("%c[FATAL NETWORK ERROR]", "color: red; font-size: 14px;", error);
        alert("Network error: The server might have timed out or crashed.");
        resetDashboard();
    }
}

// Make executeAudit global
window.executeAudit = executeAudit;

document.addEventListener("DOMContentLoaded", verifyConnection);
document.addEventListener("DOMContentLoaded", init);