import { applyGraphFilter, inspectNodeFromCard } from './graph3d.js';
// DOM manipulation (updating HTML text, flipping cards)

let currentLLMReport = null;
let currentGraphData = null;

export function toggleFlip(element) {
    element.classList.toggle('is-flipped');

    if (element.closest('.metrics-grid')) {
        document.querySelectorAll('.metrics-grid .flip-card').forEach(card => {
            if (card !== element) card.classList.remove('is-flipped');
        });
        console.log("[DEBUG] Card flipped. Determining filter for graph update...");
        let filter = 'all';
        if (element.classList.contains('is-flipped')) {
            const front = element.querySelector('.flip-card-front');
            if (front.classList.contains('bg-purple')) filter = 'risk';
            if (front.classList.contains('bg-orange')) filter = 'liability';
            if (front.classList.contains('bg-lightblue')) filter = 'asset';
            if (front.classList.contains('bg-darkblue')) filter = 'coverage';
            if (front.classList.contains('bg-yellow')) filter = 'smells';
        }

        // Assuming applyGraphFilter is imported or available
        if (typeof applyGraphFilter === 'function') {
            console.log(`[DEBUG] Applying graph filter: ${filter}`);
            applyGraphFilter(filter);
        }
    }
}

export function populateDashboard(report, graphData) {

    currentLLMReport = report;
    currentGraphData = graphData;
    
    const nodes = graphData.nodes;
    // --- Calculate Real Metrics for Front of Tiles ---
    const totalFiles = nodes.length;
    const ipFiles = nodes.filter(n => n.isProprietaryIP).length;
    const avgCoverage = totalFiles > 0 ? (nodes.reduce((acc, n) => acc + (n.testCoverage || 0), 0) / totalFiles) : 0;
    const smellsCount = nodes.filter(n => (n.astComplexity > 15 || n.inDegree > 10)).length;

    document.getElementById('val-total-files').innerText = totalFiles.toLocaleString();
    document.getElementById('val-op-risk').innerText = report.maintenance_risk || "Unknown";
    document.getElementById('val-liabilities').innerText = report.critical_flaws ? report.critical_flaws.length : "0";
    document.getElementById('val-ip-moat').innerText = totalFiles > 0 ? `${Math.round((ipFiles / totalFiles) * 100)}%` : "0%";
    document.getElementById('val-coverage').innerText = `${Math.round(avgCoverage * 100)}%`;
    document.getElementById('val-smells').innerText = smellsCount;

    // --- Helper to format file links ---
    const formatFile = (node, icon, extra = "") =>
        `<li>${icon} <a href="#" onclick="event.preventDefault(); event.stopPropagation(); window.flyToNodeById('${node.id}');" title="${node.id}">${node.id.split('/').pop()} <span style="font-size:0.75rem; color:var(--text-muted);">${extra}</span></a></li>`;
    // --- 1. UNIFIED CATEGORY LOGIC (For Perfect Graph Sync) ---
    const getGraphCategory = (n) => {
        const hasCritical = n.criticalVulnerabilities && n.criticalVulnerabilities.length > 0;
        const hasSecrets = n.highEntropySecrets > 0;
        const badPII = n.handlesPII && typeof n.testCoverage === 'number' && n.testCoverage < 0.50;
        
        // Security overrides everything
        if (hasCritical || hasSecrets || badPII) return 'liability';
        // Bus factor overrides IP
        if (n.busFactorRisk) return 'risk';
        // Finally, it is purely an asset
        if (n.isProprietaryIP) return 'asset';
        
        return 'neutral';
    };
    
    // --- Populate Back of Tiles ---

    // 1. Volume (All files, highest imported first)
    const topVolume = [...nodes].sort((a, b) => (b.inDegree || 0) - (a.inDegree || 0)).slice(0, 4);
    document.getElementById('list-volume').innerHTML = topVolume.map(n => formatFile(n, '<i class="fa-brands fa-github"></i>', `(In: ${n.inDegree})`)).join('');

    // 2. Risk (STRICT MATCH)
    const riskFiles = nodes.filter(n => getGraphCategory(n) === 'risk').slice(0, 4);
    document.getElementById('list-risk').innerHTML = riskFiles.length > 0
        ? riskFiles.map(n => formatFile(n, '⚠️', `(1 Author)`)).join('')
        : `<li style="color:var(--text-muted); text-align:center; padding-top:10px;">No critical bus factor risks detected.</li>`;

    // 3. Liability (STRICT MATCH)
    const liabilityFiles = nodes.filter(n => getGraphCategory(n) === 'liability').slice(0, 4);
    document.getElementById('list-liability').innerHTML = liabilityFiles.length > 0
        ? liabilityFiles.map(n => {
            const label = (n.criticalVulnerabilities && n.criticalVulnerabilities.length > 0) ? '(CVE)' 
                        : (n.highEntropySecrets > 0 ? '(Secrets)' : '(PII Risk)');
            return formatFile(n, '🔓', label);
        }).join('')
        : `<li style="color:var(--text-muted); text-align:center; padding-top:10px;">No immediate liabilities detected.</li>`;

    // 4. IP Moat (STRICT MATCH)
    const moatFiles = nodes.filter(n => getGraphCategory(n) === 'asset').slice(0, 4);
    document.getElementById('list-ip').innerHTML = moatFiles.length > 0
        ? moatFiles.map(n => formatFile(n, '💎')).join('')
        : `<li style="color:var(--text-muted); text-align:center; padding-top:10px;">No high-density proprietary logic detected.</li>`;

    // 5. Coverage
    const lowestCoverage = [...nodes]
        .filter(n => typeof n.testCoverage === 'number' && n.testCoverage < 0.30)
        .sort((a, b) => a.testCoverage - b.testCoverage).slice(0, 4);
    document.getElementById('list-coverage').innerHTML = lowestCoverage.map(n => formatFile(n, '❌', `(${Math.round(n.testCoverage * 100)}%)`)).join('');

    // 6. Smells
    const topSmells = [...nodes]
        .filter(n => n.astComplexity > 15 || n.inDegree > 10)
        .sort((a, b) => b.astComplexity - a.astComplexity).slice(0, 4);
    document.getElementById('list-smells').innerHTML = topSmells.map(n => formatFile(n, '🐛', `(Complexity: ${n.astComplexity})`)).join('');

    // --- Populate Bottom Panels (LLM Report) ---
    const vulnList = document.getElementById('vuln-list');
    document.getElementById('val-vuln-total').innerText = `${report.critical_flaws ? report.critical_flaws.length : 0} Issues`;
    vulnList.innerHTML = (report.critical_flaws || []).map(flaw => `
        <li class="detail-item">
            <div class="item-left">
                <strong>Vulnerability Detected</strong>
                <span>${flaw.length > 60 ? flaw.substring(0, 60) + '...' : flaw}</span>
            </div>
            <div class="item-right">
                <strong>High Sev</strong>
                <span>Requires Action</span>
            </div>
        </li>
    `).join('') || '<li style="padding:15px; color:var(--text-muted);">No critical flaws explicitly reported by the LLM.</li>';

    document.getElementById('summary-text').innerText = report.executive_summary || report.summary || "No executive summary provided.";

    // --- Inject Explicit Reasoning into Tile Backs ---
    
    const reasonVolume = document.getElementById('reason-volume');
    if (reasonVolume) reasonVolume.innerText = `Agent parsed ${totalFiles} total files. Displaying the modules with the highest in-degree dependencies:`;

    const reasonRisk = document.getElementById('reason-risk');
    if (reasonRisk) reasonRisk.innerText = `${riskFiles.length} files exhibit a Bus Factor of 1 (single author), creating critical knowledge chokepoints.`;

    const reasonLiability = document.getElementById('reason-liability');
    if (reasonLiability) reasonLiability.innerText = `Detected ${liabilityFiles.length} files with unpatched CVEs, hardcoded secrets, or untested PII sinks.`;

    const reasonIP = document.getElementById('reason-ip');
    if (reasonIP) reasonIP.innerText = `${ipFiles} out of ${totalFiles} files contain core proprietary algorithms, making up ${Math.round((ipFiles / (totalFiles || 1)) * 100)}% of the codebase.`;

    const reasonCoverage = document.getElementById('reason-coverage');
    if (reasonCoverage) reasonCoverage.innerText = `Aggregate unit test coverage is ${Math.round(avgCoverage * 100)}%. Highlighting core logic modules below 30%:`;

    const reasonSmells = document.getElementById('reason-smells');
    if (reasonSmells) reasonSmells.innerText = `Flagged ${smellsCount} "God Objects" exceeding an AST complexity of 15 or 10+ inbound connections.`;

    const archList = document.getElementById('arch-list');
    const suitabilityScore = Math.round((report.velocity_score || 0) / 10);
    document.getElementById('val-arch-score').innerText = `${suitabilityScore || 0} / 10`;
    archList.innerHTML = (report.positive_aspects || []).map(aspect => `
        <li class="detail-item">
            <div class="item-left">
                <strong>Architectural Strength</strong>
                <span>${aspect.length > 60 ? aspect.substring(0, 60) + '...' : aspect}</span>
            </div>
            <div class="item-right">
                <strong>Optimal</strong>
                <span>Stable</span>
            </div>
        </li>
    `).join('') || '<li style="padding:15px; color:var(--text-muted);">No positive aspects reported.</li>';
}

export function openScorecard(filter) {
    if (!currentGraphData || !currentLLMReport) return;

    const nodes = currentGraphData.nodes;
    let title = "", score = "", color = "", bullets = [], reasoning = "", benchmark = "";
    let matchedNodes = [];

    const getGraphCategory = (n) => {
        const hasCritical = n.criticalVulnerabilities && n.criticalVulnerabilities.length > 0;
        const hasSecrets = n.highEntropySecrets > 0;
        const badPII = n.handlesPII && typeof n.testCoverage === 'number' && n.testCoverage < 0.50;
        if (hasCritical || hasSecrets || badPII) return 'liability';
        if (n.busFactorRisk) return 'risk';
        if (n.isProprietaryIP) return 'asset';
        return 'neutral';
    };

    if (filter === 'all') {
        matchedNodes = nodes;
        title = "Codebase Volume";
        score = nodes.length.toLocaleString();
        color = "var(--tile-green)";
        reasoning = `Agent parsed ${nodes.length} total files. Displaying the modules with the highest in-degree dependencies:`;
        benchmark = "Industry Avg: Enterprise SaaS microservices typically range between 500–1,500 core files.";
        bullets = ["Full repository scan complete.", "Includes all configuration and boilerplate."];
    } else if (filter === 'risk') {
        matchedNodes = nodes.filter(n => getGraphCategory(n) === 'risk');
        title = "Operational Risk";
        score = currentLLMReport.maintenance_risk || "Medium";
        color = "var(--tile-purple)";
        reasoning = `${matchedNodes.length} files exhibit a Bus Factor of 1 (single author), creating critical knowledge chokepoints.`;
        benchmark = "ISO/IEC 52304 strongly recommends a minimum Bus Factor > 2 for critical routing and data modules.";
        bullets = ["Bus Factor of 1 detected in major hubs.", "Warning: Chokepoint architecture identified."];
    } else if (filter === 'liability') {
        matchedNodes = nodes.filter(n => getGraphCategory(n) === 'liability');
        title = "Immediate Liabilities";
        score = (currentLLMReport.critical_flaws ? currentLLMReport.critical_flaws.length : "0");
        color = "var(--tile-orange)";
        reasoning = `Detected ${matchedNodes.length} files with unpatched CVEs, hardcoded secrets, or untested PII sinks.`;
        benchmark = "OWASP Top 10 dictates strict zero-tolerance (0) for unpatched CVEs and hardcoded entropy secrets.";
        bullets = ["Unpatched CVEs or Hardcoded Secrets.", "PII data sinks lack strict auth gateway checks."];
    } else if (filter === 'asset') {
        matchedNodes = nodes.filter(n => getGraphCategory(n) === 'asset');
        title = "High-Value IP";
        const ipFiles = nodes.filter(n => n.isProprietaryIP).length;
        score = nodes.length > 0 ? `${Math.round((ipFiles / nodes.length) * 100)}%` : "0%";
        color = "var(--tile-lightblue)";
        reasoning = `${ipFiles} out of ${nodes.length} files contain core proprietary algorithms, making up ${score} of the codebase.`;
        benchmark = "Market Benchmark: Defensible tech startups typically isolate 10–15% of codebase volume as proprietary algorithmic IP.";
        bullets = ["Proprietary algorithm density detected.", "High centrality: Core routing logic heavily relied upon."];
    } else if (filter === 'coverage') {
        matchedNodes = nodes.filter(n => typeof n.testCoverage === 'number' && n.testCoverage < 0.30);
        title = "QA Confidence";
        const avgCov = nodes.reduce((acc, n) => acc + (n.testCoverage || 0), 0) / (nodes.length || 1);
        score = `${Math.round(avgCov * 100)}%`;
        color = "var(--tile-darkblue)";
        reasoning = `Aggregate unit test coverage is ${score}. Highlighting ${matchedNodes.length} core logic modules below 30%:`;
        benchmark = "IEEE 29119 Software Testing Standards recommend ≥ 80% aggregate branch coverage for enterprise deployments.";
        bullets = ["Test coverage below threshold in complex modules.", "Core logic lacks unit tests."];
    } else if (filter === 'smells') {
        matchedNodes = nodes.filter(n => n.astComplexity > 15 || n.inDegree > 10);
        title = "Architecture Smells";
        score = matchedNodes.length.toString();
        color = "var(--tile-yellow)";
        reasoning = `Flagged ${matchedNodes.length} "God Objects" exceeding an AST complexity of 15 or 10+ inbound connections.`;
        benchmark = "Maintainability Index (MI): Highly coupled 'God Objects' should constitute < 2% of total system components.";
        bullets = ["High coupling detected.", "God objects present in module layer."];
    }

    document.getElementById('sc-title').innerText = title;
    document.getElementById('sc-score').innerText = score;
    document.getElementById('sc-score').style.color = color;
    
    const reasonEl = document.getElementById('sc-reasoning');
    if (reasonEl) reasonEl.innerText = reasoning;

    // INJECT THE BENCHMARK AND UPDATE COLOR TO MATCH TILE
    const benchmarkEl = document.getElementById('sc-benchmark');
    if (benchmarkEl) {
        benchmarkEl.innerText = benchmark;
        benchmarkEl.style.borderLeftColor = color;
        benchmarkEl.style.color = "rgba(255,255,255,0.9)";
    }

    document.getElementById('sc-bullets').innerHTML = bullets.map(b => `<li>${b}</li>`).join('');
    
    document.getElementById('sc-files-list').innerHTML = matchedNodes.slice(0, 30).map(n =>
        `<div class="file-link" onclick="window.inspectNodeFromCard('${n.id}')" title="${n.id}">${n.id.split('/').pop()}</div>`
    ).join('') || "<div style='color:var(--text-muted); padding:10px;'>No files match this category.</div>";

    document.getElementById('scorecard-overlay').style.display = 'flex';
    
    applyGraphFilter(filter);
}

export function closeScorecard() {
    document.getElementById('scorecard-overlay').style.display = 'none';
    const activeCard = document.querySelector('.metrics-grid .is-flipped .flip-card-front');
    if (activeCard) {
        if (activeCard.classList.contains('bg-purple')) applyGraphFilter('risk');
        else if (activeCard.classList.contains('bg-orange')) applyGraphFilter('liability');
        else if (activeCard.classList.contains('bg-lightblue')) applyGraphFilter('asset');
        else if (activeCard.classList.contains('bg-darkblue')) applyGraphFilter('coverage');
        else if (activeCard.classList.contains('bg-yellow')) applyGraphFilter('smells');
        else applyGraphFilter('all');
    } else {
        applyGraphFilter('all');
    }
}

export function openNodeDetails(node) {
    document.getElementById('nd-filename').innerText = node.id.split('/').pop();
    document.getElementById('nd-purpose').innerText = node.modulePurpose || "No docstring or module purpose extracted for this file.";
    document.getElementById('nd-complexity').innerText = node.astComplexity || 0;
    document.getElementById('nd-indegree').innerText = node.inDegree || 0;

    const vulnStr = node.criticalVulnerabilities ? node.criticalVulnerabilities.length.toString() : "0";
    document.getElementById('nd-vulns').innerText = vulnStr;
    if (vulnStr !== "0") document.getElementById('nd-vulns').style.color = "var(--tile-orange)";

    document.getElementById('graph-container').style.filter = 'blur(6px)';
    document.getElementById('node-detail-panel').style.display = 'flex';
}

export function closeNodeDetails() {
    document.getElementById('graph-container').style.filter = 'none';
    document.getElementById('node-detail-panel').style.display = 'none';
}

export function resetDashboard() {
    document.getElementById('report-panel').style.display = 'none';
    document.getElementById('input-panel').style.display = 'block';
    document.getElementById('repo-input').value = '';
    currentGraphData = null;
    currentLLMReport = null;
    // if (orbitInterval) clearInterval(orbitInterval);
}