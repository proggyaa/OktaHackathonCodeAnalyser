/**
 * graph3d.js
 * ─────────────────────────────────────────────────────────────────────────────
 * VC Codebase Auditor — Interactive Dependency Graph Module
 *
 * Responsibilities:
 *   • Render a 2-D force-directed dependency graph via `3d-force-graph`.
 *   • Categorise every node (liability / risk / asset / neutral).
 *   • Tune the d3-force physics to avoid the classic "hairball / black-hole"
 *     collapse that plagues large codebase graphs.
 *   • Expose a clean public API consumed by the parent dashboard shell.
 *
 * Globals expected from host page:
 *   • ForceGraph3D  (from 3d-force-graph UMD bundle)
 *   • d3            (from d3 UMD bundle — required for forceCollide)
 *
 * Public API:
 *   render3DGraph(graphData)        – Mount and draw the graph.
 *   applyGraphFilter(filter)        – Highlight a category / metric subset.
 *   inspectNodeFromCard(nodeId)     – Fly the camera to a node by id.
 * ─────────────────────────────────────────────────────────────────────────────
 */

// ─── Module-scoped state ─────────────────────────────────────────────────────
const SpriteText = window.SpriteText;
const THREE = window.THREE;
/** @type {object|null} The ForceGraph3D instance, kept alive across calls. */
let graph = null;

/**
 * Caches the last full data set so that filter functions can reference it
 * without needing a second argument.
 * @type {{ nodes: object[], links: object[] }|null}
 */
let _graphData = null;

/**
 * Holds any active orbit / animation interval so it can be cancelled on the
 * next node click.
 * @type {number|null}
 */
let _orbitInterval = null;
let _currentAngle = 0; // Tracks the orbital position

// ─── Colour palette ──────────────────────────────────────────────────────────

/**
 * Full-opacity category colours (RGBA strings).
 * @readonly
 */
const CATEGORY_COLORS = Object.freeze({
  liability: 'rgba(217, 83,  79,  1)',
  risk:      'rgba(240, 173, 78,  1)',
  asset:     'rgba(91,  192, 222, 1)',
  neutral:   'rgba(66,  153, 225, 1)',
});

/**
 * 60 % alpha versions used on links so edges don't visually dominate nodes.
 * @readonly
 */
const LINK_COLORS = Object.freeze({
  liability: 'rgba(217, 83,  79,  0.6)',
  risk:      'rgba(240, 173, 78,  0.6)',
  asset:     'rgba(91,  192, 222, 0.6)',
  neutral:   'rgba(66,  153, 225, 0.6)',
  unknown:   'rgba(66,  153, 225, 0.4)',
});

/** Colour used to visually "dim" nodes / links that don't match a filter. */
const DIM_NODE_COLOR = 'rgba(200, 200, 200, 0.15)';
const DIM_LINK_COLOR = 'rgba(200, 200, 200, 0.08)';

// ─── Helper — node categorisation ────────────────────────────────────────────

/**
 * Determine the risk / value category of a single node.
 *
 * Priority order (first matching rule wins):
 *   1. liability — has critical vulnerabilities, high-entropy secrets, or
 *                  handles PII with <50 % test coverage.
 *   2. risk      — single point-of-failure (bus-factor risk).
 *   3. asset     — contains proprietary IP worth protecting.
 *   4. neutral   — everything else.
 *
 * @param {object} node
 * @returns {'liability'|'risk'|'asset'|'neutral'}
 */
function getNodeCategory(node) {
  const hasCriticalVulns =
    Array.isArray(node.criticalVulnerabilities) &&
    node.criticalVulnerabilities.length > 0;

  const hasHighEntropySecrets =
    typeof node.highEntropySecrets === 'number' &&
    node.highEntropySecrets > 0;

  const isPIIWithPoorCoverage =
    node.handlesPII === true &&
    typeof node.testCoverage === 'number' &&
    node.testCoverage < 0.50;

  if (hasCriticalVulns || hasHighEntropySecrets || isPIIWithPoorCoverage) {
    return 'liability';
  }

  if (node.busFactorRisk === true) {
    return 'risk';
  }

  if (node.isProprietaryIP === true) {
    return 'asset';
  }

  return 'neutral';
}

// ─── Helper — node visual size ────────────────────────────────────────────────

/**
 * Map a node's raw `val` weight to a clamped visual radius.
 * Square-root scaling prevents a handful of very large files from visually
 * overwhelming the rest of the graph.
 *
 * @param {object} node
 * @returns {number}  Value in [1, 6].
 */
function getNodeSize(node) {
  return Math.min(Math.max(Math.sqrt(node.val || 2), 1), 6);
}

// ─── Helper — resolve source node from a link object ─────────────────────────

/**
 * After d3-force resolves the graph, `link.source` is mutated from a plain
 * id-string into the actual node object. This helper normalises both cases so
 * colour / size callbacks always receive a node object.
 *
 * @param {object|string} sourceRef
 * @returns {object|null}
 */
function resolveSourceNode(sourceRef) {
  if (sourceRef && typeof sourceRef === 'object') return sourceRef;

  if (_graphData && typeof sourceRef === 'string') {
    return _graphData.nodes.find((n) => n.id === sourceRef) ?? null;
  }

  return null;
}

// ─── Physics tuning ──────────────────────────────────────────────────────────

/**
 * Override the default d3-force settings on the graph instance to prevent
 * the "hairball / black-hole" collapse that happens with large codebases.
 *
 * Must be called AFTER the graph has been initialised (i.e., after
 * ForceGraph3D() returns) because some forces are registered lazily.
 *
 * @param {object} graphInstance  The ForceGraph3D instance.
 */
function tunePhysics(graphInstance) {
  // 1. Stop the simulation early so nodes settle quickly and the browser
  //    doesn't hang animating a fully-converged graph forever.
  graphInstance.cooldownTicks(100);

  // 2. Charge / repulsion — spread nodes out and cap the influence radius so
  //    distant unrelated clusters don't attract each other.
  graphInstance
    .d3Force('charge')
    ?.strength(-150)
    .distanceMax(600);

  // 3. Dynamic link distance — "God objects" (high in-degree hubs) get pushed
  //    further from their neighbours so they don't visually collapse into a
  //    single point; normal nodes stay clustered for readability.
  graphInstance.d3Force('link')?.distance((link) => {
    const src = resolveSourceNode(link.source);
    const tgt = resolveSourceNode(link.target);

    const srcInDegree = src?.inDegree ?? 0;
    const tgtInDegree = tgt?.inDegree ?? 0;

    return srcInDegree > 30 || tgtInDegree > 30 ? 150 : 40;
  });

  // 4. Collision — prevent nodes from overlapping by assigning each one a
  //    radius proportional to its visual size.
  graphInstance.d3Force(
    'collide',
    d3.forceCollide((node) => Math.sqrt(node.val || 2) * 2),
  );
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Starts a continuous 60FPS rotation of the camera around the (0,0,0) origin.
 */
// TODO: This 
function startOrbit() {
    if (!graph) return;
    if (_orbitInterval) clearInterval(_orbitInterval);

    _orbitInterval = setInterval(() => {
        // 1. Get the current camera state
        const camera = graph.camera(); 
        const controls = graph.controls(); // Access the internal OrbitControls
        
        // 2. Instead of setting position, we rotate the camera around its current target
        // This allows the user to 'Right-Click Pan' the target away from (0,0,0)
        // and the rotation will follow that new center.
        
        const angle = Math.PI / 600;
        
        // Rotate the camera around the Y axis of its current target
        const pos = graph.cameraPosition();
        const target = controls.target; // This is the 'Center' the user moved with right-click

        // Math: Rotate point (pos) around point (target)
        const dx = pos.x - target.x;
        const dz = pos.z - target.z;
        
        const cos = Math.cos(angle);
        const sin = Math.sin(angle);
        
        const newX = target.x + (dx * cos - dz * sin);
        const newZ = target.z + (dx * sin + dz * cos);

        graph.cameraPosition(
            { x: newX, y: pos.y, z: newZ },
            target, // Look at the CURRENT target (allows for panning!)
            0
        );
    }, 1000 / 60);
}
/**
 * Mount the 3-D force graph (rendered flat in 2-D) inside `#graph-container`
 * and draw the supplied dependency graph data.
 *
 * Calling `render3DGraph` a second time re-uses the same DOM element and
 * tears down the previous instance cleanly.
 *
 * @param {{ nodes: object[], links: object[] }} graphData
 */
function render3DGraph(graphData) {
  if (!graphData || !Array.isArray(graphData.nodes)) {
    console.error('[graph3d] render3DGraph: invalid graphData supplied.', graphData);
    return;
  }

  // Persist for later use by filter / inspect helpers.
  _graphData = graphData;

  // ── Container ────────────────────────────────────────────────────────────
  const container = document.getElementById('graph-container');
  if (!container) {
    console.error('[graph3d] render3DGraph: #graph-container element not found.');
    return;
  }

  // Tear down any existing instance to avoid multiple canvases stacking.
  if (graph) {
    graph._destructor?.();
    container.innerHTML = '';
    graph = null;
  }

  // Cancel any lingering orbit animation from a previous session.
  if (_orbitInterval !== null) {
    clearInterval(_orbitInterval);
    _orbitInterval = null;
  }

  // Dynamically measure the available space
    const width = container.offsetWidth;
    const height = container.offsetHeight || 500;

  // ── Initialise graph ──────────────────────────────────────────────────────
  graph = ForceGraph3D()(container)
    .width(width)
    .height(height)
    // Flat 2-D layout — all z coordinates are fixed at 0.
    .numDimensions(3)

    // Transparent background so the parent container's CSS gradient shows.
    .backgroundColor('rgba(0,0,0,0)')

    // ── Data ───────────────────────────────────────────────────────────────
    .graphData(graphData)

    // ── Node appearance ────────────────────────────────────────────────────
    .nodeColor((node) => CATEGORY_COLORS[getNodeCategory(node)])
    .nodeVal((node)   => getNodeSize(node))

    // Rich tooltip: file path + key risk signals.
    .nodeLabel((node) => {
      const category = getNodeCategory(node);
      const coverage = typeof node.testCoverage === 'number'
        ? `${(node.testCoverage * 100).toFixed(0)}%`
        : 'n/a';

      return [
        `<strong>${node.id}</strong>`,
        `Category : ${category}`,
        `In / Out  : ${node.inDegree ?? 0} / ${node.outDegree ?? 0}`,
        `Coverage  : ${coverage}`,
      ].join('<br/>');
    })

    // ── Link appearance ────────────────────────────────────────────────────
    .linkColor((link) => {
      const src = resolveSourceNode(link.source);
      if (!src) return LINK_COLORS.unknown;
      return LINK_COLORS[getNodeCategory(src)] ?? LINK_COLORS.unknown;
    })
    .linkWidth(1.2)

    // ── Interactivity ──────────────────────────────────────────────────────
    .onNodeHover((node) => {
      container.style.cursor = node ? 'pointer' : 'default';
    })
    .onNodeClick((node) => 
        {_flyToNode(node)

        setTimeout(() => {
        showNodeDetails(node);
    }, 1000);
    })
    // Inside the ForceGraph3D() configuration chain:
    // Inside the ForceGraph3D() configuration chain in graph3d.js
    .onBackgroundClick(() => {
        if (_orbitInterval) {
            // 1. If it's spinning, STOP it
            console.log("[DEBUG] Background clicked: Stopping orbit.");
            clearInterval(_orbitInterval);
            _orbitInterval = null;
        } else {
            // 2. If it's stopped, START it
            console.log("[DEBUG] Background clicked: Starting orbit.");
            startOrbit();
        }
    })
    .nodeThreeObjectExtend(true)
    .nodeThreeObject(node => {
        // 1. Extract filename for the label
        const filename = node.id.split('/').pop();
        const sprite = new SpriteText(filename);
        
        // 2. Setup Appearance
        sprite.color = '#ffffff'; 
        sprite.fontWeight = 'bold';
        
        // Use your existing helper to scale text relative to node size
        const nodeSize = getNodeSize(node);
        sprite.textHeight = Math.max(nodeSize * 0.7, 3); 
        
        // 3. The "Stay on Top" Fixes
        // This prevents the sphere from "eating" the text
        sprite.material.depthTest = false; 
        
        // This ensures the text is drawn AFTER the nodes in the render loop
        sprite.renderOrder = 999; 

        // 4. Position (Optional)
        // If you want it dead center, keep (0,0,0). 
        // If it's still hard to read, offset it slightly: sprite.position.y = -(nodeSize + 2);
        sprite.position.set(0, 0, 0);
        
        return sprite;
    })
    ;

  // ── Physics ───────────────────────────────────────────────────────────────
  tunePhysics(graph);

  setTimeout(() => {
    startOrbit();
}, 1000);
}

// ─── Private — camera flight helper ──────────────────────────────────────────

/**
 * Smoothly fly the camera to a given node object.
 *
 * The distance formula keeps the camera far enough back that the node's full
 * label is visible, while `lookAt` ensures the node stays centred on screen.
 *
 * @param {object} node  A node object from the graph data.
 */
function _flyToNode(node) {
  console.log(`[graph3d] Flying to node: ${node.id}`);
  if (!graph || !node) return;
  // Cancel any active orbit / auto-rotate interval.
  if (_orbitInterval !== null) {
    clearInterval(_orbitInterval);
    _orbitInterval = null;
  }

  const CAMERA_DISTANCE = 80;
  const ANIMATION_MS    = 1000;

  // In 2-D mode the z coordinate is always 0; we still pass it explicitly for
  // future-proofing if numDimensions is ever toggled at runtime.
  const x = node.x ?? 0;
  const y = node.y ?? 0;
  const z = node.z ?? 0;

  graph.cameraPosition(
    // New camera position — directly "above" the node along the z-axis.
    { x, y, z: z + CAMERA_DISTANCE },
    // Look-at target — the node itself.
    { x, y, z },
    // Transition duration in milliseconds.
    ANIMATION_MS,
  );
    setTimeout(() => {
                showNodeDetails(node);
            }, 800);
}

// ─── Private — Node Details Modal ────────────────────────────────────────────

/**
 * Populates and displays the detail overlay using the new 
 * 'node-detail-panel' structure.
 */
/**
 * NEW: Populates the detail overlay using your specific HTML IDs
 *
 */
function showNodeDetails(node) {
    const panel = document.getElementById('node-detail-panel');
    if (!panel) return;
    console.log(`[DEBUG][graph3d] showNodeDetails: Populating details for node:`, node);
    // 1. Filename Extraction
    document.getElementById('nd-filename').textContent = node.id.split('/').pop();

    // 2. Strict Categorization & Reasoning Logic
    const hasCritical = node.criticalVulnerabilities && node.criticalVulnerabilities.length > 0;
    const hasSecrets = node.highEntropySecrets > 0;
    const badPII = node.handlesPII && typeof node.testCoverage === 'number' && node.testCoverage < 0.50;

    let catName = "Standard Component";
    let catReason = "Standard architectural module with no severe risks or isolated proprietary IP detected.";
    let catColor = "#48bb78"; // Green (Neutral/Safe)

    // Security overrides everything
    if (hasCritical || hasSecrets || badPII) {
        catName = "Immediate Liability";
        catColor = "#fc8181"; // Red
        if (hasCritical) {
            catReason = `Flagged as a liability due to ${node.criticalVulnerabilities.length} explicitly identified CVEs or structural flaws.`;
        } else if (hasSecrets) {
            catReason = `Flagged as a liability due to ${node.highEntropySecrets} hardcoded high-entropy secrets.`;
        } else {
            catReason = `Flagged as a liability: Handles PII data but lacks sufficient test coverage (${Math.round(node.testCoverage * 100)}% < 50%).`;
        }
    }// Bus factor overrides IP
    else if (node.busFactorRisk) {
        catName = "Operational Risk";
        catColor = "#b794f4"; // Purple
        catReason = "Flagged as a maintenance risk due to a Bus Factor of 1 (single primary author) on a highly dependent module.";
    } 
    // Finally, check if it's an asset
    else if (node.isProprietaryIP) {
        catName = "High-Value IP (Asset)";
        catColor = "#63b3ed"; // Light Blue
        catReason = "Flagged as a core asset due to a high density of proprietary algorithms, unique mathematics, or core business logic.";
    }

    // 3. Inject Category Reasoning
    const container = document.getElementById('nd-classification-container');
    container.style.borderLeftColor = catColor;
    const nameEl = document.getElementById('nd-category-name');
    nameEl.textContent = catName;
    nameEl.style.color = catColor;
    
    document.getElementById('nd-category-reason').textContent = catReason;
    
    // 2. Module Purpose mapping
    document.getElementById('nd-purpose').textContent = node.modulePurpose || "No semantic analysis available for this module.";

    // 3. Stats Mapping
    document.getElementById('nd-complexity').textContent = node.astComplexity || 0;
    document.getElementById('nd-indegree').textContent = node.inDegree || 0;

    // 4. Vulnerability Count
    const vulnCount = Array.isArray(node.criticalVulnerabilities) ? node.criticalVulnerabilities.length : 0;
    const vulnEl = document.getElementById('nd-vulns');
    vulnEl.textContent = vulnCount;
    vulnEl.style.color = vulnCount > 0 ? '#fc8181' : '#48bb78';

    // 5. Reveal Panel
    panel.style.display = 'block';
}
/**
 * Global helper to close the overlay.
 */
window.closeNodeDetails = function() {
    const panel = document.getElementById('node-detail-panel');
    if (panel) panel.style.display = 'none';
};

// ─── Public — filter API ──────────────────────────────────────────────────────

/**
 * Highlight a subset of nodes/links matching the supplied filter key.
 * Non-matching nodes are dimmed to `rgba(200, 200, 200, 0.15)` so they
 * recede into the background without disappearing entirely.
 *
 * Supported filter values:
 *   'all'       — Reset; show every node at full colour and default size.
 *   'liability' — Nodes with critical vulnerabilities / secrets / PII risk.
 *   'risk'      — Bus-factor risk nodes.
 *   'asset'     — Proprietary IP nodes.
 *   'coverage'  — Nodes with test coverage < 30 %.
 *   'smells'    — Nodes with inDegree > 10 OR astComplexity > 15.
 *
 * @param {'all'|'liability'|'risk'|'asset'|'coverage'|'smells'} filter
 */
function applyGraphFilter(filter) {
  if (!graph) {
    console.warn('[DEBUG][graph3d] applyGraphFilter: No graph instance found.');
    return;
  }

  console.log(`[DEBUG][graph3d] applyGraphFilter: Starting filter sequence for: "${filter}"`);

  /**
   * Returns true when a node should be "highlighted" by the current filter.
   */
  function isNodeMatch(node) {
    let match = false;
    switch (filter) {
      case 'all':
        match = true;
        break;
      case 'liability':
      case 'risk':
      case 'asset':
        match = getNodeCategory(node) === filter;
        break;
      case 'coverage':
        match = (typeof node.testCoverage === 'number' && node.testCoverage < 0.30);
        break;
      case 'smells':
        match = ((node.inDegree ?? 0) > 10 || (node.astComplexity ?? 0) > 15);
        break;
      default:
        console.warn(`[DEBUG][graph3d] Unknown filter type: ${filter}`);
        match = true;
    }
    return match;
  }

  // ── Node colour ────────────────────────────────────────────────────────────
  graph.nodeColor((node) => {
    const isMatch = isNodeMatch(node);
    if (!isMatch) return DIM_NODE_COLOR;
    
    const color = CATEGORY_COLORS[getNodeCategory(node)];
    // Log only matches to avoid console flooding
    console.log(`[DEBUG][graph3d] Node Match Found: ${node.id} | Category: ${getNodeCategory(node)}`);
    return color;
  });

  // ── Node size ──────────────────────────────────────────────────────────────
  graph.nodeVal((node) => {
    const isMatch = isNodeMatch(node);
    if (!isMatch) return 0.5;
    
    const size = filter === 'all' ? getNodeSize(node) : getNodeSize(node) * 1.5;
    return size;
  });

  // ── Link colour / width ────────────────────────────────────────────────────
  graph.linkColor((link) => {
    const src = resolveSourceNode(link.source);
    const tgt = resolveSourceNode(link.target);

    if (!src || !tgt) {
      console.error(`[DEBUG][graph3d] Link resolution failed for Source: ${link.source} or Target: ${link.target}`);
      return LINK_COLORS.unknown;
    }

    if (filter !== 'all' && (!isNodeMatch(src) || !isNodeMatch(tgt))) {
      return DIM_LINK_COLOR;
    }

    return LINK_COLORS[getNodeCategory(src)] ?? LINK_COLORS.unknown;
  });

  graph.linkWidth((link) => {
    if (filter === 'all') return 1.2;

    const src = resolveSourceNode(link.source);
    const tgt = resolveSourceNode(link.target);

    if (!src || !tgt) return 0.3;

    const bothMatch = isNodeMatch(src) && isNodeMatch(tgt);
    if (bothMatch) {
       console.log(`[DEBUG][graph3d] Highlighting Link: ${src.id} -> ${tgt.id}`);
    }
    return bothMatch ? 2.0 : 0.3;
  });
  
  console.log(`[DEBUG][graph3d] applyGraphFilter: Logic applied to render loop.`);
}
// ─── Public — external card → graph inspection ───────────────────────────────

/**
 * Fly the camera to the node identified by `nodeId`.
 *
 * Called from outside this module — e.g., when the user clicks a node card in
 * the sidebar rather than the graph canvas itself.
 *
 * @param {string} nodeId  The `id` (filepath) of the node to inspect.
 */
function inspectNodeFromCard(nodeId) {
  if (!graph) {
    console.warn('[graph3d] inspectNodeFromCard called before render3DGraph.');
    return;
  }

  if (!_graphData) return;

  const targetNode = _graphData.nodes.find((n) => n.id === nodeId);

  if (!targetNode) {
    console.warn(`[graph3d] inspectNodeFromCard: node "${nodeId}" not found.`);
    return;
  }

  _flyToNode(targetNode);
}

/**
 * NEW: Allows external UI (like flip cards) to trigger a flight to a specific node.
 */
window.flyToNodeById = function(nodeId) {
    if (!_graphData || !Array.isArray(_graphData.nodes)) return;
    
    // Find the exact node object from the JSON data
    const targetNode = _graphData.nodes.find(n => n.id === nodeId);
    
    if (targetNode) {
        // 1. Fly the camera
        _flyToNode(targetNode);
        
        // 2. Open the popup after flight finishes (800ms)
        setTimeout(() => {
            showNodeDetails(targetNode);
        }, 800);
    } else {
        console.warn(`[Graph3D] Could not find node with id: ${nodeId}`);
    }
};

// ─── Exports ──────────────────────────────────────────────────────────────────

export { render3DGraph, applyGraphFilter, inspectNodeFromCard };