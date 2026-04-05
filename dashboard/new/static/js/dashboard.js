/* ================================================================
   SINK TRACER — Dashboard Client (MaterialM Dark Theme)
   Cytoscape.js graph + WebSocket event dispatcher
   ================================================================ */

// ── Sink color palette (MaterialM) ─────────────────────────────

const SINK_COLORS = [
  { main: '#ff6692', dim: '#4b313d', glow: 'rgba(255,102,146,0.25)' },
  { main: '#ffae1f', dim: '#4d3a2a', glow: 'rgba(255,174,31,0.25)' },
  { main: '#8965e5', dim: '#2a2047', glow: 'rgba(137,101,229,0.25)' },
  { main: '#46caeb', dim: '#1b3040', glow: 'rgba(70,202,235,0.25)' },
  { main: '#00ceb6', dim: '#1b3c48', glow: 'rgba(0,206,182,0.25)' },
  { main: '#00a1ff', dim: '#002040', glow: 'rgba(0,161,255,0.25)' },
];

const BACKTRACK_COLOR = '#ffae1f';
const SOURCE_COLOR = '#00ceb6';
const ACCENT = '#00a1ff';
const BG_VOID = '#111c2d';
const BG_SURFACE = '#1f2a3d';
const TEXT_DIM = 'rgba(255,255,255,0.3)';
const TEXT_SEC = 'rgba(255,255,255,0.6)';

// ── Label helpers ───────────────────────────────────────────────

function shortenLabel(name, maxLen = 30) {
  return name;
}

function getDisplayLabel(name, maxLen = 30) {
  return name;
}

// ── State ───────────────────────────────────────────────────────

const state = {
  sinks: {},
  sinkCount: 0,
  activeNodeId: null,
  activeStep: null,
  activeSinkId: null,
  currentChain: [],
  nodesMeta: {},
  stats: { nodes: 0, edges: 0, chains: 0, backtracks: 0 },
  isRunning: false,
  isComplete: false,
  pipeline: 'full',
  smtResults: {},
  smtActiveNode: null,
  taintFlows: {},
  smtConstraints: {},
  smtNodeConstraints: {},
  smtTimeline: [],
  unsatCoreDetails: [],
  pocSummary: null,
  repairLog: [],
  panelVisible: true,
};


// ── Cytoscape initialization ────────────────────────────────────

const cy = cytoscape({
  container: document.getElementById('cy'),
  layout: { name: 'preset' },
  minZoom: 0.15,
  maxZoom: 3.5,
  wheelSensitivity: 0.3,
  boxSelectionEnabled: false,
  style: [
    // ── Default node ──
    {
      selector: 'node',
      style: {
        'label':              'data(label)',
        'font-family':        "'JetBrains Mono', monospace",
        'font-size':          10,
        'font-weight':        500,
        'color':              TEXT_SEC,
        'text-valign':        'bottom',
        'text-halign':        'center',
        'text-margin-y':      8,
        'text-outline-width': 2,
        'text-outline-color': BG_VOID,
        'text-outline-opacity': 1,
        'text-wrap':          'ellipsis',
        'text-max-width':     140,
        'width':              28,
        'height':             28,
        'shape':              'round-rectangle',
        'corner-radius':      6,
        'background-color':   '#253247',
        'border-width':       1.5,
        'border-color':       '#3d4d66',
        'overlay-opacity':    0,
        'overlay-color':      ACCENT,
        'overlay-padding':    4,
        'transition-property': 'background-color, border-color, border-width, width, height, opacity',
        'transition-duration': '0.6s',
        'z-index':            10,
      },
    },
    // ── Sink node (diamond) ──
    {
      selector: 'node.sink',
      style: {
        'shape':              'diamond',
        'width':              34,
        'height':             34,
        'font-weight':        700,
        'font-size':          11,
        'z-index':            20,
      },
    },
    // ── Source node (hexagon) ──
    {
      selector: 'node.source',
      style: {
        'shape':              'hexagon',
        'width':              36,
        'height':             36,
        'background-color':   '#1b3c48',
        'border-color':       SOURCE_COLOR,
        'border-width':       2.5,
        'color':              SOURCE_COLOR,
        'font-weight':        700,
        'font-size':          11,
        'z-index':            20,
      },
    },
    // ── Active chain node ──
    {
      selector: 'node.on-chain',
      style: {
        'border-width':       2,
        'z-index':            15,
      },
    },
    // ── Explored but not on current chain ──
    {
      selector: 'node.explored',
      style: {
        'background-color':   '#1a2537',
        'border-color':       '#313e54',
        'color':              'rgba(255,255,255,0.35)',
      },
    },
    // ── Dimmed ──
    {
      selector: 'node.dimmed',
      style: {
        'opacity':            0.25,
      },
    },
    {
      selector: 'edge.dimmed',
      style: {
        'opacity':            0.12,
      },
    },
    // ── Dead end (backtracked) ──
    {
      selector: 'node.dead-end',
      style: {
        'background-color':   '#4d3a2a',
        'border-color':       BACKTRACK_COLOR,
        'border-style':       'dashed',
        'color':              'rgba(255,174,31,0.5)',
      },
    },
    // ── Default edge ──
    {
      selector: 'edge',
      style: {
        'width':              1.5,
        'line-color':         '#313e54',
        'target-arrow-color': '#313e54',
        'target-arrow-shape': 'triangle',
        'arrow-scale':        0.7,
        'curve-style':        'bezier',
        'opacity':            0.7,
        'transition-property': 'line-color, target-arrow-color, width, opacity',
        'transition-duration': '0.6s',
      },
    },
    // ── Active chain edge ──
    {
      selector: 'edge.on-chain',
      style: {
        'width':              2.5,
        'opacity':            1,
        'line-style':         'dashed',
        'line-dash-pattern':  [8, 4],
        'z-index':            15,
      },
    },
    // ── Backtrack edge ──
    {
      selector: 'edge.backtrack',
      style: {
        'line-color':         BACKTRACK_COLOR,
        'target-arrow-color': BACKTRACK_COLOR,
        'line-style':         'dashed',
        'line-dash-pattern':  [4, 6],
        'width':              1.5,
        'opacity':            0.6,
      },
    },
    // ── Registration edge ──
    {
      selector: 'edge.registration',
      style: {
        'line-style':         'dotted',
        'line-dash-pattern':  [2, 4],
      },
    },
    // ── SMT node status styles ──
    {
      selector: 'node.smt-sat',
      style: {
        'border-color':       '#00ceb6',
        'border-width':       2.5,
        'background-color':   '#1b3c48',
      },
    },
    {
      selector: 'node.smt-unsat',
      style: {
        'border-color':       '#ff6692',
        'border-width':       2.5,
        'border-style':       'double',
        'background-color':   '#4b313d',
      },
    },
    {
      selector: 'node.smt-unknown',
      style: {
        'border-color':       '#ffae1f',
        'border-width':       2,
        'border-style':       'dashed',
        'background-color':   '#4d3a2a',
      },
    },
    {
      selector: 'node.smt-skipped',
      style: {
        'opacity':            0.5,
      },
    },
    // ── Deterministic registration node ──
    {
      selector: 'node.det-registration',
      style: {
        'border-color':       SOURCE_COLOR,
        'border-width':       2.5,
        'border-style':       'solid',
      },
    },
    // ── Wrapper sink badge ──
    {
      selector: 'node.wrapper-sink',
      style: {
        'text-border-width':  1,
        'text-border-color':  '#8965e5',
        'text-border-opacity': 1,
      },
    },
    // ── Foreign-binary node ──
    {
      selector: 'node.foreign-binary',
      style: {
        'border-color':       '#8965e5',
        'border-width':       2,
        'border-style':       'dashed',
        'background-color':   '#2a2047',
        'color':              '#8965e5',
      },
    },
    // ── Cross-driver edge ──
    {
      selector: 'edge.cross-driver',
      style: {
        'line-color':         '#8965e5',
        'target-arrow-color': '#8965e5',
        'line-style':         'dashed',
        'line-dash-pattern':  [6, 4],
        'width':              2,
        'label':              '',
        'font-size':          8,
        'color':              '#8965e5',
        'text-rotation':      'autorotate',
      },
    },
    // ── Solid green registration edge ──
    {
      selector: 'edge.det-registration',
      style: {
        'line-style':         'solid',
        'line-color':         SOURCE_COLOR,
        'target-arrow-color': SOURCE_COLOR,
        'width':              2.5,
      },
    },
  ],
});

// ── Layout management ───────────────────────────────────────────

let layoutTimer = null;
let layoutRunning = false;

function scheduleLayout() {
  if (layoutTimer) clearTimeout(layoutTimer);
  layoutTimer = setTimeout(runLayout, 600);
}

function runLayout() {
  if (layoutRunning) return;
  if (cy.nodes().length === 0) return;

  layoutRunning = true;
  const layout = cy.layout({
    name: 'dagre',
    rankDir: 'BT',
    nodeSep: 55,
    rankSep: 80,
    edgeSep: 10,
    ranker: 'network-simplex',
    acyclicer: 'greedy',
    animate: true,
    animationDuration: 900,
    animationEasing: 'ease-in-out-sine',
    fit: false,
    padding: 50,
    nodeDimensionsIncludeLabels: true,
  });
  layout.on('layoutstop', () => { layoutRunning = false; });
  layout.run();
}

// ── Node pulse animation ────────────────────────────────────────

let pulseAnimationId = null;
let pulseNode = null;

function startPulse(nodeId) {
  stopPulse();
  const node = cy.getElementById(nodeId);
  if (!node || node.length === 0) return;
  pulseNode = node;

  let phase = 0;
  const tick = () => {
    if (!pulseNode) return;
    phase += 0.04;
    const val = 0.08 + 0.2 * (0.5 + 0.5 * Math.sin(phase * Math.PI * 2));
    const pad = 4 + 10 * (0.5 + 0.5 * Math.sin(phase * Math.PI * 2));
    try {
      pulseNode.style({
        'overlay-opacity': val,
        'overlay-padding': pad,
      });
    } catch (e) {}
    pulseAnimationId = requestAnimationFrame(tick);
  };
  tick();
}

function stopPulse() {
  if (pulseAnimationId) cancelAnimationFrame(pulseAnimationId);
  pulseAnimationId = null;
  if (pulseNode) {
    try {
      pulseNode.style({ 'overlay-opacity': 0, 'overlay-padding': 4 });
    } catch (e) {}
  }
  pulseNode = null;
}

// ── Edge flow animation ─────────────────────────────────────────

let dashOffset = 0;

function animateEdgeFlow() {
  if (state.isComplete) return;
  dashOffset -= 0.6;
  const chainEdges = cy.edges('.on-chain');
  if (chainEdges.length > 0) {
    chainEdges.style('line-dash-offset', dashOffset);
  }
  requestAnimationFrame(animateEdgeFlow);
}
animateEdgeFlow();

// ── Sink color management ───────────────────────────────────────

function getSinkColor(sinkId) {
  if (!state.sinks[sinkId]) return SINK_COLORS[0];
  return SINK_COLORS[state.sinks[sinkId].index % SINK_COLORS.length];
}

function applySinkColorToNode(nodeId, sinkId) {
  const c = getSinkColor(sinkId);
  const node = cy.getElementById(nodeId);
  if (node.length === 0) return;
  node.style({
    'border-color': c.main,
    'background-color': c.dim,
    'color': c.main,
    'overlay-color': c.main,
  });
}

function applySinkColorToEdge(edgeId, sinkId) {
  const c = getSinkColor(sinkId);
  const edge = cy.getElementById(edgeId);
  if (edge.length === 0) return;
  edge.style({
    'line-color': c.main,
    'target-arrow-color': c.main,
  });
}

// ── DOM helpers ─────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function updateStats() {
  $('#stat-nodes').textContent = state.stats.nodes;
  $('#stat-edges').textContent = state.stats.edges;
  $('#stat-chains').textContent = state.stats.chains;
  $('#stat-backtracks').textContent = state.stats.backtracks;
}

function setStatus(type, text) {
  const badge = $('#status-badge');
  badge.className = `badge badge-${type}`;
  $('#status-text').textContent = text;
}

function setActiveNode(name, addr) {
  $('#active-node-name').textContent = name || '—';
  $('#active-node-addr').textContent = addr || '—';

  const prototypeDiv = document.getElementById('function-prototype');
  if (prototypeDiv) {
    prototypeDiv.textContent = "test prototype not available set function";
  }
}

function setStep(step, label) {
  $$('.step-pip').forEach(el => {
    const s = el.dataset.step;
    el.classList.remove('active', 'done');
    if (s === step) {
      el.classList.add('active');
    } else if (step && s < step) {
      el.classList.add('done');
    }
  });
  $('#step-description').textContent = label || '—';
}

function updateChainList(chain, sinkId) {
  const container = $('#chain-list');
  container.innerHTML = '';
  const color = getSinkColor(sinkId);

  for (let i = 0; i < chain.length; i++) {
    const nid = chain[i];
    const meta = state.nodesMeta[nid] || {};

    if (i > 0) {
      const arrow = document.createElement('div');
      arrow.className = 'chain-arrow';
      arrow.textContent = '\u2191';
      container.appendChild(arrow);
    }

    const el = document.createElement('div');
    el.className = 'chain-node';

    if (i === 0 && meta.isSink) {
      el.classList.add('chain-sink');
    } else if (meta.isSource) {
      el.classList.add('chain-source');
    } else if (nid === state.activeNodeId) {
      el.classList.add('chain-active');
    } else {
      el.classList.add('chain-normal');
    }

    el.textContent = meta.label || nid;
    container.appendChild(el);
  }

  container.scrollTop = container.scrollHeight;
}

function updateClassification(roles) {
  const container = $('#classification-badges');
  container.innerHTML = '';
  if (!roles || roles.length === 0) {
    container.innerHTML = '<span class="dim small">—</span>';
    return;
  }
  for (const role of roles) {
    const el = document.createElement('span');
    el.className = 'class-badge';
    if (role.includes('sink') || role.includes('dangerous'))     el.classList.add('role-sink');
    else if (role.includes('entry') || role.includes('source'))  el.classList.add('role-source');
    else if (role.includes('dispatch') || role.includes('demux')) el.classList.add('role-dispatch');
    else el.classList.add('role-default');
    el.textContent = role;
    container.appendChild(el);
  }
}

function addLogEntry(text, type = '') {
  const log = $('#event-log');
  const el = document.createElement('div');
  el.className = 'log-entry' + (type ? ` log-${type}` : '');
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  el.textContent = `[${ts}] ${text}`;
  log.appendChild(el);

  while (log.children.length > 100) {
    log.removeChild(log.firstChild);
  }
  log.scrollTop = log.scrollHeight;
}

// ── Panel toggle ────────────────────────────────────────────────

function togglePanel() {
  const panel = document.getElementById('panel');
  const main = document.getElementById('main-content');
  const btn = document.getElementById('panel-toggle');

  state.panelVisible = !state.panelVisible;

  if (state.panelVisible) {
    panel.classList.remove('collapsed');
    main.classList.remove('panel-collapsed');
    btn.classList.remove('panel-hidden');
  } else {
    panel.classList.add('collapsed');
    main.classList.add('panel-collapsed');
    btn.classList.add('panel-hidden');
  }

  // Resize graph after transition
  setTimeout(() => { cy.resize(); }, 360);
}

// ── Event handlers ──────────────────────────────────────────────

const handlers = {
  server_ready(d) {
    $('#waiting-overlay').classList.add('hidden');
    setStatus('running', 'ANALYZING');
    state.isRunning = true;
    state.pipeline = d.pipeline || 'trace_only';

    if (state.pipeline === 'trace_only') {
      for (const id of ['smt-status-section', 'poc-witness-section', 'unsat-core-section']) {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
      }
      addLogEntry(`Trace started: ${d.file || 'unknown'} (${d.mode || 'full'})`, 'important');
    } else {
      addLogEntry(`Pipeline started: ${d.file || 'unknown'} (${d.mode || 'full'}, tracer+SMT)`, 'important');
    }
  },

  sink_added(d) {
    const idx = state.sinkCount++;
    state.sinks[d.id] = { index: idx, chain: [] };
    const color = SINK_COLORS[idx % SINK_COLORS.length];

    if (cy.getElementById(d.id).length === 0) {
      cy.add({
        group: 'nodes',
        data: { id: d.id, label: getDisplayLabel(d.label || d.id) },
        classes: 'sink',
      });
      state.stats.nodes++;

      const node = cy.getElementById(d.id);
      node.style({
        'background-color': color.dim,
        'border-color': color.main,
        'color': color.main,
        'border-width': 2.5,
        'overlay-color': color.main,
      });
    }

    state.nodesMeta[d.id] = {
      label: d.label || d.id,
      roles: ['sink'],
      sinkId: d.id,
      isSink: true,
    };

    updateStats();
    scheduleLayout();
    addLogEntry(`Sink: ${d.label}`, 'important');

    const sinkNode = cy.getElementById(d.id);
    if (sinkNode.length > 0) {
      cy.animate({ center: { eles: sinkNode }, duration: 800, easing: 'ease-in-out-sine' });
    }
  },

  node_discovered(d) {
    if (cy.getElementById(d.id).length > 0) return;

    cy.add({
      group: 'nodes',
      data: { id: d.id, label: getDisplayLabel(d.label || d.id) },
    });
    state.stats.nodes++;

    state.nodesMeta[d.id] = state.nodesMeta[d.id] || {
      label: d.label || d.id,
      roles: [],
      sinkId: d.sink_id || null,
      prototype: d.prototype || null,
    };

    if (d.sink_id) {
      applySinkColorToNode(d.id, d.sink_id);
    }

    cy.getElementById(d.id).addClass('explored');
    updateStats();
    scheduleLayout();
  },

  edge_added(d) {
    const edgeId = `${d.source}->${d.target}`;
    if (cy.getElementById(edgeId).length > 0) return;

    const classes = [];
    if (d.edge_type === 'registration') classes.push('registration');

    cy.add({
      group: 'edges',
      data: { id: edgeId, source: d.source, target: d.target },
      classes: classes.join(' '),
    });
    state.stats.edges++;

    if (d.sink_id) {
      const c = getSinkColor(d.sink_id);
      cy.getElementById(edgeId).style({
        'line-color':         c.main,
        'target-arrow-color': c.main,
        'opacity':            0.45,
      });
    }

    updateStats();
    scheduleLayout();
  },

  node_active(d) {
    state.activeNodeId = d.id;
    state.activeStep = d.step;
    state.activeSinkId = d.sink_id || state.activeSinkId;

    const meta = state.nodesMeta[d.id] || {};

    setActiveNode(meta.label || d.id, d.id);
    setStep(d.step, d.step_label || stepLabels[d.step] || d.step);
    setStatus('running', `STEP ${d.step}`);

    startPulse(d.id);
  },

  node_classified(d) {
    const meta = state.nodesMeta[d.id] || {};
    meta.roles = d.roles || [];
    meta.confidence = d.confidence || 0;
    state.nodesMeta[d.id] = meta;

    updateClassification(meta.roles);
    addLogEntry(`Classified ${meta.label || d.id}: ${(meta.roles || []).join(', ') || '—'}`);
  },

  chain_updated(d) {
    const chain = d.chain || [];
    const sinkId = d.sink_id || state.activeSinkId;
    state.currentChain = chain;

    const color = getSinkColor(sinkId);

    cy.batch(() => {
      cy.elements().removeClass('on-chain dimmed');
      cy.elements().addClass('dimmed');

      for (const nid of chain) {
        const n = cy.getElementById(nid);
        if (n.length > 0) {
          n.removeClass('dimmed').addClass('on-chain');
          n.style({
            'border-color': color.main,
            'background-color': color.dim,
            'color': color.main,
          });
        }
      }

      for (let i = 0; i < chain.length - 1; i++) {
        const src = chain[i + 1];
        const tgt = chain[i];
        const edgeId = `${src}->${tgt}`;
        const edge = cy.getElementById(edgeId);
        if (edge.length > 0) {
          edge.removeClass('dimmed').addClass('on-chain');
          edge.style({
            'line-color': color.main,
            'target-arrow-color': color.main,
          });
        }
        const edgeIdRev = `${tgt}->${src}`;
        const edgeRev = cy.getElementById(edgeIdRev);
        if (edgeRev.length > 0) {
          edgeRev.removeClass('dimmed').addClass('on-chain');
          edgeRev.style({
            'line-color': color.main,
            'target-arrow-color': color.main,
          });
        }
      }

      cy.nodes('.explored').style('opacity', '');
      cy.nodes('.sink').removeClass('dimmed');
      cy.nodes('.source').removeClass('dimmed');

      for (const [sid, sdata] of Object.entries(state.sinks)) {
        if (sid !== sinkId && sdata.chain && sdata.chain.length > 0) {
          for (const nid of sdata.chain) {
            cy.getElementById(nid).removeClass('dimmed');
          }
        }
      }
    });

    updateChainList(chain, sinkId);
  },

  backtrack_start(d) {
    state.stats.backtracks++;
    updateStats();
    setStatus('backtrack', 'BACKTRACK');

    cy.getElementById(d.from_id).addClass('dead-end');

    const edgeId1 = `${d.from_id}->${d.to_id}`;
    const edgeId2 = `${d.to_id}->${d.from_id}`;
    for (const eid of [edgeId1, edgeId2]) {
      const e = cy.getElementById(eid);
      if (e.length > 0) e.addClass('backtrack');
    }

    addLogEntry(`Backtrack: ${state.nodesMeta[d.from_id]?.label || d.from_id} \u2192 ${state.nodesMeta[d.to_id]?.label || d.to_id} (${d.reason})`, 'warn');

    const btNode = cy.getElementById(d.to_id);
    if (btNode.length > 0) {
      cy.animate({ center: { eles: btNode }, duration: 800, easing: 'ease-in-out-sine' });
    }
  },

  source_found(d) {
    state.stats.chains++;
    updateStats();

    const sinkId = d.sink_id || state.activeSinkId;
    if (state.sinks[sinkId]) {
      state.sinks[sinkId].chain = d.chain || [];
    }

    const node = cy.getElementById(d.id);
    if (node.length > 0) {
      node.addClass('source').removeClass('explored dimmed');
    }

    const meta = state.nodesMeta[d.id] || {};
    meta.isSource = true;
    meta.roles = [...(meta.roles || []), 'source'];
    state.nodesMeta[d.id] = meta;

    stopPulse();
    addLogEntry(`SOURCE FOUND: ${meta.label || d.id} (${d.stop_kind || 'unknown'})`, 'success');

    if (node.length > 0) {
      cy.animate({ center: { eles: node }, duration: 800, easing: 'ease-in-out-sine' });
    }
    cy.elements().removeClass('dimmed on-chain');
    setTimeout(() => {
      if (d.chain) {
        handlers.chain_updated({ chain: d.chain, sink_id: sinkId });
        cy.elements().removeClass('dimmed');
      }
    }, 800);
  },

  vote_result(d) {
    addLogEntry(`Vote: ${d.candidates?.length || 0} candidates, winner: ${state.nodesMeta[d.winner]?.label || d.winner || '?'}`);
  },

  analysis_complete(d) {
    stopPulse();
    setStep(null);
    cy.elements().removeClass('dimmed on-chain');
    runLayout();

    if (state.pipeline === 'full') {
      setStatus('running', 'SMT SOLVING');
      addLogEntry(`Tracing complete: ${d.findings} chain(s), ${d.incomplete} incomplete. Starting SMT...`, 'success');
    } else {
      state.isRunning = false;
      state.isComplete = true;
      setStatus('complete', 'COMPLETE');
      addLogEntry(`Analysis complete: ${d.findings} chain(s) found, ${d.incomplete} incomplete`, 'success');
    }
  },

  error(d) {
    setStatus('backtrack', 'ERROR');
    const lines = (d.message || 'Unknown error').split('\n');
    for (const line of lines) {
      if (line.trim()) addLogEntry(line, 'warn');
    }
  },

  pipeline_complete(d) {
    state.isRunning = false;
    state.isComplete = true;
    stopPulse();
    setStatus('complete', 'COMPLETE');

    const summaries = d.smt_summaries || [];
    const satCount = summaries.filter(s => s.status === 'sat').length;
    const unsatCount = summaries.filter(s => s.status === 'unsat').length;
    const totalSolved = d.findings_solved || summaries.length;

    let msg = `Pipeline complete: ${totalSolved} finding(s) solved`;
    if (satCount > 0) msg += `, ${satCount} SAT`;
    if (unsatCount > 0) msg += `, ${unsatCount} UNSAT`;
    addLogEntry(msg, 'success');
  },

  // ── SMT Events ──

  smt_stage_start(d) {
    if (state.pipeline !== 'full') return;
    setStatus('running', 'SMT');
    addLogEntry(`SMT stage started: ${d.total_constraints || 0} constraints`, 'important');
  },

  smt_constraints_summary(d) {
    if (state.pipeline !== 'full') return;
    const section = document.getElementById('smt-constraints-section');
    if (section) section.classList.remove('hidden');

    const breakdown = d.breakdown || {};
    const total = d.total || 1;
    const container = document.getElementById('constraint-breakdown');
    if (!container) return;

    const segments = [
      { cls: 'seg-mined', count: breakdown.mined || 0, label: 'Mined' },
      { cls: 'seg-llm', count: breakdown.llm || 0, label: 'LLM' },
      { cls: 'seg-domain', count: breakdown.domain || 0, label: 'Domain' },
      { cls: 'seg-structural', count: breakdown.structural || 0, label: 'Structural' },
    ];

    let html = '<div class="constraint-bar">';
    for (const seg of segments) {
      const pct = ((seg.count / total) * 100).toFixed(1);
      html += `<div class="constraint-bar-seg ${seg.cls}" style="width:${pct}%" title="${seg.label}: ${seg.count}"></div>`;
    }
    html += '</div><div class="constraint-bar-legend">';
    for (const seg of segments) {
      html += `<div class="constraint-legend-item"><div class="constraint-legend-dot ${seg.cls}"></div>${seg.label}: ${seg.count}</div>`;
    }
    html += '</div>';
    html += `<div class="dim small" style="margin-top:4px">Hard: ${d.hard_count || 0} | Soft: ${d.soft_count || 0} | Z3 vars: ${d.z3_variables || 0} | Skipped: ${d.z3_skipped || 0}</div>`;

    container.innerHTML = html;

    addLogEntry(`Constraints: ${total} total (${breakdown.mined || 0} mined, ${breakdown.llm || 0} LLM, ${breakdown.domain || 0} domain)`);
  },

  smt_node_status(d) {
    if (state.pipeline !== 'full') return;
    const node = cy.getElementById(d.ea);
    if (node.length > 0) {
      node.removeClass('smt-sat smt-unsat smt-unknown smt-skipped');
      node.addClass(`smt-${d.status}`);
    }

    if (d.core_ids && d.core_ids.length > 0) {
      if (!state.smtResults._coreIds) state.smtResults._coreIds = [];
      for (const cid of d.core_ids) {
        if (!state.smtResults._coreIds.includes(cid)) {
          state.smtResults._coreIds.push(cid);
        }
      }
    }

    const constraints = d.constraints || [];
    if (constraints.length > 0) {
      state.smtNodeConstraints[d.ea] = constraints;
      for (const c of constraints) {
        state.smtConstraints[c.id] = c;
      }
    }

    state.smtTimeline.push({
      ea: d.ea,
      name: d.name,
      status: d.status,
      constraints_added: d.constraints_added,
    });

    renderSolverTimeline();
    renderConstraintList();

    const statusIcon = d.status === 'sat' ? '+' : d.status === 'unsat' ? '!' : '?';
    const type = d.status === 'sat' ? '' : 'warn';
    addLogEntry(`SMT [${statusIcon}] ${d.name} (${d.ea}): ${d.status} +${d.constraints_added}`, type);

    if (d.is_first_fail) {
      addLogEntry(`  First failure at ${d.name}: ${d.reason || d.status}`, 'warn');
      if (node.length > 0) {
        cy.animate({ center: { eles: node }, duration: 500 });
      }
    }
  },

  smt_complete(d) {
    if (state.pipeline !== 'full') return;
    const section = $('#smt-status-section');
    section.classList.remove('hidden');

    const badge = $('#smt-status-badge');
    badge.className = `smt-badge smt-${d.status}`;
    badge.textContent = d.status.toUpperCase();

    const stats = $('#smt-stats');
    const parts = [`${d.total_constraints} constraints`, `${d.elapsed_ms}ms`];
    if (d.status === 'sat') parts.push(`${d.model_count} bindings`);
    if (d.status === 'unsat') parts.push(`${d.unsat_core_count} core`);
    if (d.repair_attempted) parts.push(`repair: ${d.repair_final_status || '?'}`);
    stats.textContent = parts.join(' | ');

    if (d.status === 'sat') {
      $('#poc-witness-section').classList.remove('hidden');
      $('#unsat-core-section').classList.add('hidden');
    } else if (d.status === 'unsat') {
      $('#poc-witness-section').classList.add('hidden');
      $('#unsat-core-section').classList.remove('hidden');

      const coreList = $('#unsat-core-list');
      coreList.innerHTML = '';
      const coreDetails = d.unsat_core_details || [];
      state.unsatCoreDetails = coreDetails;

      if (coreDetails.length > 0) {
        for (const c of coreDetails) {
          const el = document.createElement('div');
          el.className = 'core-entry';
          const kindBadge = `<span class="ckind-badge ${getConstraintKindClass(c.kind)}">${c.kind || '?'}</span>`;
          const nodeName = state.nodesMeta[c.node_ea]?.label || c.node_ea || '?';
          el.innerHTML = `${kindBadge} <span style="color:var(--text-secondary)">${nodeName}</span> ${c.comment || c.id}`;
          coreList.appendChild(el);
        }

        const explEl = document.getElementById('unsat-core-explanation');
        if (explEl) {
          explEl.textContent = `${coreDetails.length} conflicting constraint(s) make this path infeasible. These constraints cannot all be true simultaneously.`;
        }
      } else {
        const coreIds = (state.smtResults._coreIds || []);
        for (const cid of coreIds) {
          const el = document.createElement('div');
          el.className = 'core-entry';
          el.textContent = cid;
          coreList.appendChild(el);
        }
      }

      highlightUnsatCore();
    } else {
      $('#poc-witness-section').classList.add('hidden');
      $('#unsat-core-section').classList.add('hidden');
    }

    const type = d.status === 'sat' ? 'success' : 'warn';
    addLogEntry(`SMT complete: ${d.status.toUpperCase()} (${d.elapsed_ms}ms)`, type);
  },

  smt_witness(d) {
    if (state.pipeline !== 'full') return;

    if (d.poc_summary) {
      state.pocSummary = d.poc_summary;
      renderPocSummary(d.poc_summary);
    }

    const container = $('#poc-witness-list');
    container.innerHTML = '';

    for (const b of (d.bindings || [])) {
      const el = document.createElement('div');
      el.className = 'witness-binding';

      const nameEl = document.createElement('span');
      nameEl.className = 'witness-name';
      nameEl.textContent = b.symbol;

      const valEl = document.createElement('span');
      valEl.className = 'witness-val';
      valEl.textContent = b.representation || String(b.value);

      el.appendChild(nameEl);
      el.appendChild(valEl);

      if (b.domain) {
        const domEl = document.createElement('span');
        domEl.className = 'witness-domain';
        domEl.textContent = b.domain;
        el.appendChild(domEl);
      }

      container.appendChild(el);
    }

    addLogEntry(`PoC witness: ${(d.bindings || []).length} bindings`, 'success');
  },

  smt_repair_attempt(d) {
    if (state.pipeline !== 'full') return;
    addLogEntry(`Repair attempt ${d.iteration}: ${d.strategy} -> ${d.status_after}`, d.status_after === 'sat' ? 'success' : 'warn');
  },

  smt_repair_detail(d) {
    if (state.pipeline !== 'full') return;
    const section = document.getElementById('smt-repair-section');
    if (section) section.classList.remove('hidden');

    state.repairLog.push(d);

    const container = document.getElementById('repair-log');
    if (!container) return;

    const entry = document.createElement('div');
    const isSuccess = d.status_after === 'sat';
    entry.className = `repair-entry ${isSuccess ? 'repair-success' : 'repair-fail'}`;

    let html = `<div class="repair-entry-header">
      <span class="strategy-name">${d.strategy || '?'} #${d.iteration || 0}</span>
      <span class="status-label stat-${d.status_after || 'unknown'}">${(d.status_after || '?').toUpperCase()}</span>
    </div>`;

    const actions = d.actions || [];
    for (const a of actions) {
      html += `<div class="repair-action">${a.action}: ${a.constraint_id}${a.reason ? ' \u2014 ' + a.reason : ''}</div>`;
    }

    if (d.guardrail_vetoes && d.guardrail_vetoes > 0) {
      html += `<div class="repair-veto">Guardrail vetoed ${d.guardrail_vetoes} action(s)</div>`;
    }

    if (d.elapsed_ms) {
      html += `<div class="dim small" style="margin-top:2px">${d.elapsed_ms}ms</div>`;
    }

    entry.innerHTML = html;
    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;

    addLogEntry(`Repair ${d.strategy} #${d.iteration}: ${d.status_after} (${actions.length} actions)`,
      isSuccess ? 'success' : 'warn');
  },

  broadened_sinks_found(d) {
    const parts = [];
    if (d.wrapper_count > 0) parts.push(`${d.wrapper_count} wrapper(s)`);
    if (d.inlined_count > 0) parts.push(`${d.inlined_count} inlined`);
    addLogEntry(`Broadened sinks: ${d.total} found (${parts.join(', ') || 'none'})`, d.total > 0 ? 'important' : '');

    if (d.wrapper_count > 0) {
      state._wrapperSinksDetected = true;
    }
  },

  domain_constraints_added(d) {
    const parts = [];
    if (d.provenance_count > 0) parts.push(`${d.provenance_count} provenance`);
    if (d.offset_count > 0) parts.push(`${d.offset_count} offset`);
    addLogEntry(`Domain constraints: ${parts.join(', ') || 'none added'}`);
  },

  deterministic_registration(d) {
    const node = cy.getElementById(d.handler_ea || d.id);
    if (node.length > 0) {
      node.addClass('det-registration');
    }
    addLogEntry(`Deterministic registration: ${d.pattern_kind} ${d.handler_name || ''} (${d.irp_major || 'N/A'})`, 'success');
  },

  taint_propagated(d) {
    const method = d.extraction_method || 'text';
    const badge = method === 'ctree' ? '[ctree]' : '[text]';
    const calleeName = d.callee_name || d.callee || '?';
    const callerName = d.caller_name || d.caller || '?';
    addLogEntry(`Taint propagated ${badge}: ${calleeName} \u2192 ${callerName}`, 'info');

    const edgeKey = `${d.callee || ''}->${d.caller || ''}`;
    state.taintFlows[edgeKey] = {
      callee: d.callee,
      caller: d.caller,
      callee_name: calleeName,
      caller_name: callerName,
      extraction_method: method,
      confidence: d.confidence || 0,
      taint_mappings: d.taint_mappings || [],
      new_taint: d.new_taint || {},
      ioctl_guard: d.ioctl_guard || null,
      ioctl_code: d.ioctl_code || null,
      sink_id: d.sink_id,
    };

    const section = document.getElementById('taint-flow-section');
    if (section) section.classList.remove('hidden');
    renderTaintFlowSection();

    const edgeId1 = `${d.caller}->${d.callee}`;
    const edgeId2 = `${d.callee}->${d.caller}`;
    for (const eid of [edgeId1, edgeId2]) {
      const edge = cy.getElementById(eid);
      if (edge.length > 0) {
        const kinds = Object.values(d.new_taint?.taint_kinds || {});
        if (kinds.length > 0) {
          edge.data('label', '');
          edge.style({ 'label': '', 'font-size': 8, 'color': 'rgba(255,255,255,0.6)', 'text-rotation': 'autorotate' });
        }
      }
    }
  },

  cross_driver_edge(d) {
    const lowerNode = cy.getElementById(d.lower_dispatch_ea);
    if (lowerNode.length === 0 && d.lower_dispatch_ea) {
      cy.add({
        group: 'nodes',
        data: { id: d.lower_dispatch_ea, label: getDisplayLabel(d.lower_dispatch_name || d.lower_dispatch_ea) },
        classes: 'foreign-binary',
      });
      state.stats.nodes++;
    } else if (lowerNode.length > 0) {
      lowerNode.addClass('foreign-binary');
    }

    if (d.io_call_driver_ea && d.lower_dispatch_ea) {
      const edgeId = `${d.io_call_driver_ea}->cross->${d.lower_dispatch_ea}`;
      if (cy.getElementById(edgeId).length === 0) {
        cy.add({
          group: 'edges',
          data: { id: edgeId, source: d.io_call_driver_ea, target: d.lower_dispatch_ea, label: 'IoCallDriver' },
          classes: 'cross-driver',
        });
        state.stats.edges++;
      }
    }

    updateStats();
    scheduleLayout();
    addLogEntry(`Cross-driver: ${d.upper_driver || '?'} -> ${d.lower_driver || '?'} via IoCallDriver`, 'important');
  },

};

const stepLabels = {
  A: 'Classifying function',
  B: 'Finding upward edges',
  C: 'Stop/continue lookahead',
  D: 'Voting on next caller',
  E: 'Propagating taint',
  F: 'Advancing to caller',
};

// ── Rendering functions ─────────────────────────────────────────

function getTaintKindClass(kind) {
  if (!kind) return 'tkind-default';
  const k = kind.toUpperCase();
  if (k.includes('PHYSICAL') || k.includes('PHYS'))   return 'tkind-phys';
  if (k.includes('BUFFER'))                            return 'tkind-buffer';
  if (k.includes('IOCTL'))                             return 'tkind-ioctl';
  if (k.includes('SIZE'))                              return 'tkind-size';
  if (k.includes('HANDLE') || k.includes('ADDRESS'))   return 'tkind-handle';
  return 'tkind-default';
}

function getConstraintKindClass(kind) {
  if (!kind) return 'ckind-default';
  if (kind.includes('branch') || kind === 'IT' || kind === 'ITE') return 'ckind-branch';
  if (kind.includes('ioctl'))      return 'ckind-ioctl_guard';
  if (kind.includes('range'))      return 'ckind-range_check';
  if (kind.includes('api'))        return 'ckind-api_contract';
  if (kind.includes('domain') || kind.includes('environment')) return 'ckind-domain';
  return 'ckind-default';
}

function renderTaintFlowSection() {
  const container = document.getElementById('taint-flow-list');
  if (!container) return;
  container.innerHTML = '';

  const flows = Object.values(state.taintFlows);
  if (flows.length === 0) return;

  for (const flow of flows) {
    const boundary = document.createElement('div');
    boundary.className = 'taint-boundary';

    let html = `<div class="taint-boundary-header">
      <span class="callee-name">${flow.callee_name}</span>
      <span class="arrow">\u2192</span>
      <span class="caller-name">${flow.caller_name}</span>
    </div>`;

    const mappings = flow.taint_mappings || [];
    for (const m of mappings) {
      const fromVar = m.from || m.callee_param || '?';
      const toVar = m.to || m.caller_arg || '?';
      const transform = m.transform || m.method || '';
      html += `<div class="taint-mapping">
        <span class="from-var">${fromVar}</span>
        <span class="arrow">\u2192</span>
        <span class="to-var">${toVar}</span>`;
      if (transform) {
        html += ` <span class="taint-transform-badge">${transform}</span>`;
      }
      html += `</div>`;
      if (m.evidence_snippet) {
        html += `<div class="taint-evidence">${m.evidence_snippet}</div>`;
      }
    }

    const kinds = (flow.new_taint || {}).taint_kinds || {};
    if (Object.keys(kinds).length > 0) {
      html += '<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:3px">';
      for (const [varName, kind] of Object.entries(kinds)) {
        html += `<span class="taint-kind-badge ${getTaintKindClass(kind)}">${varName}: ${kind}</span>`;
      }
      html += '</div>';
    }

    if (flow.ioctl_guard || flow.ioctl_code) {
      const guardText = flow.ioctl_code ? `IOCTL ${flow.ioctl_code}` : flow.ioctl_guard;
      html += `<div class="taint-guard">GUARD: ${guardText}</div>`;
    }

    boundary.innerHTML = html;
    container.appendChild(boundary);
  }
}

function renderSolverTimeline() {
  const container = document.getElementById('smt-solver-timeline');
  if (!container) return;
  container.innerHTML = '';

  for (const phase of state.smtTimeline) {
    const el = document.createElement('div');
    el.className = 'solver-phase';
    el.innerHTML = `
      <div class="solver-phase-pip phase-${phase.status}"></div>
      <span class="solver-phase-name">${phase.name}</span>
      <span class="solver-phase-count">+${phase.constraints_added}</span>
    `;
    el.addEventListener('click', () => {
      const node = cy.getElementById(phase.ea);
      if (node.length > 0) {
        cy.animate({ center: { eles: node }, duration: 500 });
      }
    });
    container.appendChild(el);
  }
}

function renderConstraintList() {
  const container = document.getElementById('constraint-detail-list');
  if (!container) return;
  container.innerHTML = '';

  const nodeEas = Object.keys(state.smtNodeConstraints);
  if (nodeEas.length === 0) return;

  for (const ea of nodeEas) {
    const constraints = state.smtNodeConstraints[ea] || [];
    if (constraints.length === 0) continue;

    const nodeName = state.nodesMeta[ea]?.label || ea;
    const group = document.createElement('div');
    group.className = 'constraint-node-group';

    const header = document.createElement('div');
    header.className = 'constraint-node-header';
    header.innerHTML = `<span>${nodeName}</span><span class="dim">${constraints.length}</span>`;
    header.addEventListener('click', () => {
      const body = group.querySelector('.constraint-node-body');
      if (body) body.classList.toggle('expanded');
    });

    const body = document.createElement('div');
    body.className = 'constraint-node-body';

    for (const c of constraints) {
      const entry = document.createElement('div');
      entry.className = 'constraint-entry';
      entry.dataset.constraintId = c.id;

      let html = `<span class="ckind-badge ${getConstraintKindClass(c.kind)}">${c.kind || '?'}</span>`;
      if (c.soft) html += ' <span class="soft-indicator">S</span>';
      html += `<div class="constraint-conf"><div class="constraint-conf-fill" style="width:${(c.confidence || 0) * 100}%"></div></div>`;
      html += `<span class="constraint-comment">${c.comment || c.id}</span>`;

      entry.innerHTML = html;
      body.appendChild(entry);
    }

    group.appendChild(header);
    group.appendChild(body);
    container.appendChild(group);
  }
}

function highlightUnsatCore() {
  const coreIds = new Set((state.smtResults._coreIds || []).concat(
    state.unsatCoreDetails.map(c => c.id)
  ));
  if (coreIds.size === 0) return;

  const entries = document.querySelectorAll('.constraint-entry');
  for (const entry of entries) {
    const cid = entry.dataset.constraintId;
    if (cid && coreIds.has(cid)) {
      entry.classList.add('in-core');
    }
  }
}

function renderPocSummary(summary) {
  const container = document.getElementById('poc-summary');
  if (!container || !summary) return;

  let html = '<div class="poc-recipe">';
  if (summary.ioctl_code) {
    html += `<span class="poc-recipe-label">IOCTL Code</span><span class="poc-recipe-value">${summary.ioctl_code}</span>`;
  }
  if (summary.input_buffer_size) {
    html += `<span class="poc-recipe-label">Input Size</span><span class="poc-recipe-value">${summary.input_buffer_size}</span>`;
  }
  if (summary.output_buffer_size) {
    html += `<span class="poc-recipe-label">Output Size</span><span class="poc-recipe-value">${summary.output_buffer_size}</span>`;
  }
  html += '</div>';

  const layout = summary.buffer_layout || [];
  if (layout.length > 0) {
    html += `<table class="poc-buffer-layout">
      <thead><tr><th>OFFSET</th><th>SIZE</th><th>VALUE</th><th>MEANING</th></tr></thead><tbody>`;
    for (const field of layout) {
      html += `<tr>
        <td class="buf-offset">${field.offset}</td>
        <td>${field.size}</td>
        <td class="buf-value">${field.value}</td>
        <td class="buf-meaning">${field.meaning || ''}</td>
      </tr>`;
    }
    html += '</tbody></table>';
  }

  container.innerHTML = html;
}

// ── WebSocket connection ────────────────────────────────────────

let ws = null;
let reconnectAttempts = 0;

function connect() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    reconnectAttempts = 0;
    addLogEntry('WebSocket connected');
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      const handler = handlers[msg.type];
      if (handler) {
        handler(msg.data);
      }
    } catch (err) {
      console.error('Event handling error:', err);
    }
  };

  ws.onclose = () => {
    addLogEntry('WebSocket disconnected, reconnecting...', 'warn');
    const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), 10000);
    reconnectAttempts++;
    setTimeout(connect, delay);
  };

  ws.onerror = () => {
    ws.close();
  };
}

// ── Node click handler ──────────────────────────────────────────

cy.on('tap', 'node', (evt) => {
  const node = evt.target;
  const id = node.id();
  const meta = state.nodesMeta[id] || {};

  setActiveNode(meta.label || id, id);
  updateClassification(meta.roles || []);

  cy.animate({ center: { eles: node }, duration: 300 });
});

cy.on('mouseover', 'node', (evt) => {
  const node = evt.target;
  const meta = state.nodesMeta[node.id()] || {};
  const fullName = meta.label || node.id();
  const displayName = node.data('label');
  if (fullName !== displayName) {
    const container = document.getElementById('cy');
    if (container) container.title = fullName;
  }
});

cy.on('mouseout', 'node', () => {
  const container = document.getElementById('cy');
  if (container) container.title = '';
});

// ── Keyboard shortcuts ──────────────────────────────────────────

document.addEventListener('keydown', (e) => {
  if (e.key === 'f' || e.key === 'F') {
    cy.animate({ fit: { padding: 60 }, duration: 500 });
  }
  if (e.key === 'r' || e.key === 'R') {
    runLayout();
  }
  if (e.key === 'p' || e.key === 'P') {
    togglePanel();
  }
});

// ── Panel toggle button ─────────────────────────────────────────

document.getElementById('panel-toggle').addEventListener('click', togglePanel);

// ── Boot ────────────────────────────────────────────────────────

connect();
addLogEntry('Dashboard initialized. Press F to fit, R to re-layout, P to toggle panel.');
