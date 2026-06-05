const THREE = window.THREE;

const architectures = [
  {
    title: "Agent Decision MLP",
    activation: "GELU",
    kind: "decision",
    topology: "Policy bottleneck -> gated action fan-out",
    colors: [
      [0.33, 0.96, 1],
      [0.48, 0.82, 1],
      [0.68, 1, 0.34],
      [1, 0.72, 0.24],
      [1, 0.35, 0.18],
      [0.96, 0.95, 0.82],
    ],
    layers: [
      { name: "Request", count: 20 },
      { name: "Intent", count: 30 },
      { name: "Policy", count: 16 },
      { name: "Tool Gate", count: 24 },
      { name: "Risk Gate", count: 18 },
      { name: "Action", count: 12 },
    ],
  },
  {
    title: "Vision Feature Mixer",
    activation: "ReLU",
    kind: "vision",
    topology: "Local receptive fields -> object class",
    colors: [
      [0.23, 0.94, 1],
      [0.42, 0.78, 1],
      [0.38, 1, 0.68],
      [0.82, 1, 0.38],
      [1, 0.72, 0.24],
      [1, 0.36, 0.22],
    ],
    layers: [
      { name: "Pixels", count: 54 },
      { name: "Edges", count: 48 },
      { name: "Texture", count: 42 },
      { name: "Parts", count: 34 },
      { name: "Object", count: 24 },
      { name: "Class", count: 10 },
    ],
  },
  {
    title: "Language Router",
    activation: "SwiGLU",
    kind: "language",
    topology: "Memory + attention skips -> token choice",
    colors: [
      [0.36, 0.96, 1],
      [0.6, 0.74, 1],
      [0.72, 0.58, 1],
      [1, 0.66, 0.28],
      [0.88, 1, 0.44],
      [1, 0.34, 0.28],
    ],
    layers: [
      { name: "Prompt", count: 18 },
      { name: "Memory", count: 24 },
      { name: "Attention", count: 40 },
      { name: "Router", count: 18 },
      { name: "Decode", count: 28 },
      { name: "Token", count: 16 },
    ],
  },
];

const paletteStops = [
  { at: 0.0, bg: 0x061a1f, low: 0x12a8c4, high: 0x7effff, name: "cyan scan" },
  { at: 0.24, bg: 0x090b12, low: 0x2c7fb2, high: 0xd8fbff, name: "white storm" },
  { at: 0.48, bg: 0x06151c, low: 0x2d87ff, high: 0x80d4ff, name: "xray pass" },
  { at: 0.68, bg: 0x050606, low: 0x31373b, high: 0xd9e0de, name: "ghost side" },
  { at: 0.82, bg: 0x190b04, low: 0xff4f24, high: 0xffd45c, name: "hot solve" },
];

const segmentColors = [
  [0.33, 0.96, 1],
  [0.5, 0.72, 1],
  [0.62, 1, 0.42],
  [1, 0.65, 0.22],
  [1, 0.3, 0.2],
];

const TAU = Math.PI * 2;

const state = {
  preset: 0,
  density: 0.52,
  seed: 11,
  paused: false,
  startedAt: performance.now(),
  pausedAt: 0,
};

const dom = {
  canvas: document.querySelector("#neural-canvas"),
  archTitle: document.querySelector("#arch-title"),
  archTopology: document.querySelector("#arch-topology"),
  layerCards: document.querySelector("#layer-cards"),
  layerName: document.querySelector("#layer-name"),
  neuronCount: document.querySelector("#neuron-count"),
  activationName: document.querySelector("#activation-name"),
  signalValue: document.querySelector("#signal-value"),
  phaseFill: document.querySelector("#phase-fill"),
  pauseButton: document.querySelector("#pause-button"),
  reseedButton: document.querySelector("#reseed-button"),
  densitySlider: document.querySelector("#density-slider"),
  presetButtons: Array.from(document.querySelectorAll(".preset")),
};

let renderer;
let scene;
let camera;
let group;
let nodes = [];
let links = [];
let nodeGeometry;
let nodeMaterial;
let lineGeometry;
let lineMaterial;
let pulseGeometry;
let pulseMaterial;
let flareGeometry;
let flareMaterial;
let scanMesh;
let animationFrame;
let random = seededRandom(state.seed);
let frameIndex = 0;

function init() {
  if (!THREE) return;
  window.lucide?.createIcons();
  renderer = new THREE.WebGLRenderer({ canvas: dom.canvas, antialias: true, alpha: true, powerPreference: "high-performance" });
  setRenderPixelRatio();
  renderer.setClearColor(0x050809, 0);

  scene = new THREE.Scene();
  camera = new THREE.PerspectiveCamera(48, 1, 0.1, 100);
  camera.position.set(0, 0.1, 8.8);
  scene.add(new THREE.AmbientLight(0xcffcff, 0.48));

  const cyan = new THREE.PointLight(0x54f4ff, 38, 14);
  cyan.position.set(-3.8, 2.8, 5);
  const hot = new THREE.PointLight(0xff9a36, 34, 14);
  hot.position.set(3.8, -2.1, 5);
  scene.add(cyan, hot);

  group = new THREE.Group();
  scene.add(group);
  bindEvents();
  rebuild();
  resize();
  animate();
}

function bindEvents() {
  window.addEventListener("resize", resize);
  dom.densitySlider.addEventListener("input", () => {
    state.density = Number(dom.densitySlider.value) / 100;
    rebuild();
  });
  dom.pauseButton.addEventListener("click", () => {
    state.paused = !state.paused;
    if (state.paused) state.pausedAt = performance.now();
    else state.startedAt += performance.now() - state.pausedAt;
    dom.pauseButton.innerHTML = state.paused ? '<i data-lucide="play"></i>' : '<i data-lucide="pause"></i>';
    window.lucide?.createIcons();
  });
  dom.reseedButton.addEventListener("click", () => {
    state.seed += 17;
    rebuild();
  });
  dom.presetButtons.forEach((button) => {
    button.addEventListener("click", () => {
      state.preset = Number(button.dataset.preset);
      dom.presetButtons.forEach((item) => item.classList.toggle("is-active", item === button));
      rebuild();
    });
  });
}

function rebuild() {
  random = seededRandom(state.seed + state.preset * 101);
  clearGroup();
  buildNodes();
  buildLinks();
  createGeometry();
  renderLayerCards();
  dom.archTitle.textContent = architectures[state.preset].title;
  dom.archTopology.textContent = architectures[state.preset].topology;
  dom.activationName.textContent = architectures[state.preset].activation;
}

function clearGroup() {
  while (group.children.length) {
    const child = group.children.pop();
    child.geometry?.dispose();
    child.material?.dispose();
  }
}

function buildNodes() {
  nodes = [];
  const arch = architectures[state.preset];
  const layerGap = arch.kind === "vision" ? 1.2 : arch.kind === "language" ? 1.3 : 1.34;
  const startX = -((arch.layers.length - 1) * layerGap) / 2;

  arch.layers.forEach((layer, layerIndex) => {
    for (let index = 0; index < layer.count; index += 1) {
      const layout = nodeLayout(arch, layer, layerIndex, index, startX, layerGap);
      nodes.push({
        layerIndex,
        index,
        count: layer.count,
        name: layer.name,
        base: layout.base,
        gridCol: layout.gridCol,
        gridRow: layout.gridRow,
        gridColumns: layout.gridColumns,
        gridRows: layout.gridRows,
        tint: colorForLayer(arch, layerIndex),
        activation: 0,
        phase: random() * Math.PI * 2,
      });
    }
  });
}

function buildLinks() {
  links = [];
  const arch = architectures[state.preset];
  const layerSets = arch.layers.map((_, layerIndex) => nodes.filter((node) => node.layerIndex === layerIndex));

  for (let layerIndex = 0; layerIndex < arch.layers.length - 1; layerIndex += 1) {
    connectLayerPair(arch, layerSets[layerIndex], layerSets[layerIndex + 1], layerIndex);
  }

  if (arch.kind === "decision") {
    connectDecisionGates(arch, layerSets);
  }

  if (arch.kind === "language") {
    connectLanguageSkips(arch, layerSets);
  }
}

function nodeLayout(arch, layer, layerIndex, index, startX, layerGap) {
  if (arch.kind === "vision") return visionNodeLayout(layer, layerIndex, index, startX, layerGap);
  if (arch.kind === "language") return languageNodeLayout(arch, layer, layerIndex, index, startX, layerGap);
  return decisionNodeLayout(arch, layer, layerIndex, index, startX, layerGap);
}

function decisionNodeLayout(arch, layer, layerIndex, index, startX, layerGap) {
  const u = normalizedIndex(index, layer.count);
  const center = (arch.layers.length - 1) / 2;
  const edgeWeight = Math.abs(layerIndex - center) / center;
  const spread = lerp(1.05, 2.35, edgeWeight);
  const gateBend = layerIndex >= 3 ? Math.sin((u - 0.5) * Math.PI) * 0.2 : 0;
  const x = startX + layerIndex * layerGap + (layerIndex === 2 ? -0.1 : layerIndex === 3 ? 0.12 : 0);
  const y = (0.5 - u) * 2 * spread + gateBend + (random() - 0.5) * 0.06;
  const z = (random() - 0.5) * (0.18 + edgeWeight * 0.42) + (layerIndex === 2 ? 0.18 : 0);
  return { base: new THREE.Vector3(x, y, z) };
}

function visionNodeLayout(layer, layerIndex, index, startX, layerGap) {
  const gridColumns = Math.ceil(Math.sqrt(layer.count * 0.78));
  const gridRows = Math.ceil(layer.count / gridColumns);
  const gridCol = index % gridColumns;
  const gridRow = Math.floor(index / gridColumns);
  const x = startX + layerIndex * layerGap + (gridCol - (gridColumns - 1) / 2) * 0.055;
  const y = ((gridRows - 1) / 2 - gridRow) * (4.55 / Math.max(1, gridRows - 1)) + (random() - 0.5) * 0.07;
  const z = (gridCol - (gridColumns - 1) / 2) * 0.25 + (layerIndex - 2.5) * 0.045;
  return { base: new THREE.Vector3(x, y, z), gridCol, gridRow, gridColumns, gridRows };
}

function languageNodeLayout(arch, layer, layerIndex, index, startX, layerGap) {
  const u = normalizedIndex(index, layer.count);
  const arc = Math.sin((layerIndex / (arch.layers.length - 1)) * Math.PI) * 0.48;
  const routerPull = layerIndex === 3 ? 0.52 : 1;
  const x = startX + layerIndex * layerGap + Math.sin(u * TAU + layerIndex * 0.6) * 0.14;
  let y = (0.5 - u) * 3.95 * routerPull + Math.sin(u * TAU * 2 + layerIndex * 0.7) * 0.18;
  if (layerIndex === 1) y += 0.46;
  if (layerIndex === 5) y *= 0.72;
  const z = Math.cos(u * TAU + layerIndex * 0.45) * 0.42 + arc + (layerIndex === 1 ? -0.32 : 0);
  return { base: new THREE.Vector3(x, y, z) };
}

function connectLayerPair(arch, from, to, layerIndex) {
  from.forEach((a) => {
    to.forEach((b) => {
      const probability = linkProbability(arch, a, b, layerIndex);
      if (random() < probability) pushLink(arch, a, b, layerIndex, probability);
    });
  });
}

function linkProbability(arch, a, b, layerIndex) {
  if (arch.kind === "vision") {
    const colDelta = Math.abs((a.gridCol || 0) / Math.max(1, (a.gridColumns || 1) - 1) - (b.gridCol || 0) / Math.max(1, (b.gridColumns || 1) - 1));
    const rowDelta = Math.abs((a.gridRow || 0) / Math.max(1, (a.gridRows || 1) - 1) - (b.gridRow || 0) / Math.max(1, (b.gridRows || 1) - 1));
    const localBias = Math.max(0, 1 - (colDelta * 1.9 + rowDelta * 2.5));
    return state.density * (0.015 + localBias * 0.46);
  }

  const distanceBias = 1 - Math.min(1, Math.abs(normalizedIndex(a.index, a.count) - normalizedIndex(b.index, b.count)) * 1.55);

  if (arch.kind === "language") {
    const routerBoost = layerIndex === 2 || layerIndex === 3 ? 0.08 : 0;
    return state.density * (0.06 + distanceBias * 0.2 + routerBoost);
  }

  const center = (arch.layers.length - 2) / 2;
  const gateBias = 1 - Math.min(1, Math.abs(layerIndex - center) / center);
  return state.density * (0.08 + distanceBias * 0.32 + gateBias * 0.16);
}

function connectDecisionGates(arch, layerSets) {
  const policy = layerSets[2];
  const action = layerSets[5];
  const gateLayers = [...layerSets[3], ...layerSets[4]];

  policy.forEach((a) => {
    gateLayers.forEach((b) => {
      if (random() < state.density * 0.32) pushLink(arch, a, b, 2, 0.75, 0.24);
    });
  });

  gateLayers.forEach((a) => {
    action.forEach((b) => {
      const targetBias = 1 - Math.min(1, Math.abs(normalizedIndex(a.index, a.count) - normalizedIndex(b.index, b.count)) * 1.2);
      if (random() < state.density * (0.1 + targetBias * 0.28)) pushLink(arch, a, b, 4, 0.68, 0.18);
    });
  });
}

function connectLanguageSkips(arch, layerSets) {
  connectSkipSet(arch, layerSets[0], layerSets[2], 0, 0.055);
  connectSkipSet(arch, layerSets[1], layerSets[3], 1, 0.09);
  connectSkipSet(arch, layerSets[2], layerSets[4], 2, 0.06);
  connectSkipSet(arch, layerSets[3], layerSets[5], 3, 0.13);
}

function connectSkipSet(arch, from, to, layerIndex, baseRate) {
  from.forEach((a) => {
    to.forEach((b) => {
      const attentionBias = 0.5 + Math.sin((a.index + 1) * (b.index + 3) * 0.17) * 0.5;
      if (random() < state.density * (baseRate + attentionBias * 0.035)) {
        pushLink(arch, a, b, layerIndex, 0.82, 0.32);
      }
    });
  });
}

function pushLink(arch, a, b, layerIndex, probability, weightBonus = 0) {
  const color = colorForLayer(arch, layerIndex);
  links.push({ a, b, color, weight: 0.24 + probability + weightBonus + random() * 0.52, phase: random() });
}

function createGeometry() {
  nodeGeometry = new THREE.BufferGeometry();
  nodeGeometry.setAttribute("position", new THREE.Float32BufferAttribute(new Array(nodes.length * 3).fill(0), 3));
  nodeGeometry.setAttribute("color", new THREE.Float32BufferAttribute(new Array(nodes.length * 3).fill(1), 3));
  nodeMaterial = new THREE.PointsMaterial({
    size: 0.062,
    vertexColors: true,
    transparent: true,
    opacity: 0.98,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  group.add(new THREE.Points(nodeGeometry, nodeMaterial));

  lineGeometry = new THREE.BufferGeometry();
  lineGeometry.setAttribute("position", new THREE.Float32BufferAttribute(new Array(links.length * 6).fill(0), 3));
  lineGeometry.setAttribute("color", new THREE.Float32BufferAttribute(new Array(links.length * 6).fill(1), 3));
  lineMaterial = new THREE.LineBasicMaterial({
    vertexColors: true,
    transparent: true,
    opacity: 0.24,
    blending: THREE.AdditiveBlending,
  });
  group.add(new THREE.LineSegments(lineGeometry, lineMaterial));

  const pulseCount = Math.min(360, Math.max(120, Math.floor(links.length * 0.16)));
  pulseGeometry = new THREE.BufferGeometry();
  pulseGeometry.setAttribute("position", new THREE.Float32BufferAttribute(new Array(pulseCount * 3).fill(0), 3));
  pulseGeometry.setAttribute("color", new THREE.Float32BufferAttribute(new Array(pulseCount * 3).fill(1), 3));
  pulseMaterial = new THREE.PointsMaterial({
    size: 0.046,
    vertexColors: true,
    transparent: true,
    opacity: 0.92,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  group.add(new THREE.Points(pulseGeometry, pulseMaterial));

  flareGeometry = new THREE.BufferGeometry();
  flareGeometry.setAttribute("position", new THREE.Float32BufferAttribute(new Array(96).fill(0), 3));
  flareGeometry.setAttribute("color", new THREE.Float32BufferAttribute(new Array(96).fill(1), 3));
  flareMaterial = new THREE.PointsMaterial({
    size: 0.16,
    vertexColors: true,
    transparent: true,
    opacity: 0.62,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  group.add(new THREE.Points(flareGeometry, flareMaterial));

  scanMesh = new THREE.Mesh(
    new THREE.PlaneGeometry(0.82, 6.25),
    new THREE.MeshBasicMaterial({
      color: 0x54f4ff,
      map: createScanTexture(),
      transparent: true,
      opacity: 0.78,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      side: THREE.DoubleSide,
    }),
  );
  scanMesh.position.z = 0.18;
  group.add(scanMesh);

  populateLinePositions();
  addLayerRails();
}

function populateLinePositions() {
  const linePos = lineGeometry.attributes.position.array;
  const lineCol = lineGeometry.attributes.color.array;
  links.forEach((link, index) => {
    const offset = index * 6;
    writeVector(linePos, offset, link.a.base);
    writeVector(linePos, offset + 3, link.b.base);
    writeMixedColor(lineCol, offset, link.color, [1, 1, 1], 0.12);
    writeMixedColor(lineCol, offset + 3, link.color, [1, 1, 1], 0.12);
  });
  lineGeometry.attributes.position.needsUpdate = true;
  lineGeometry.attributes.color.needsUpdate = true;
}

function addLayerRails() {
  const arch = architectures[state.preset];
  for (let layerIndex = 0; layerIndex < arch.layers.length; layerIndex += 1) {
    const layerNodes = nodes.filter((node) => node.layerIndex === layerIndex);
    const x = layerNodes[0].base.x;
    const points = [new THREE.Vector3(x, 2.5, -0.18), new THREE.Vector3(x, -2.5, -0.18)];
    const rail = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints(points),
      new THREE.LineBasicMaterial({ color: 0x95fff5, transparent: true, opacity: 0.22 }),
    );
    group.add(rail);
  }
}

function createScanTexture() {
  const canvas = document.createElement("canvas");
  canvas.width = 128;
  canvas.height = 8;
  const context = canvas.getContext("2d");
  const gradient = context.createLinearGradient(0, 0, canvas.width, 0);
  gradient.addColorStop(0, "rgba(255,255,255,0)");
  gradient.addColorStop(0.32, "rgba(255,255,255,0.08)");
  gradient.addColorStop(0.5, "rgba(255,255,255,0.42)");
  gradient.addColorStop(0.68, "rgba(255,255,255,0.08)");
  gradient.addColorStop(1, "rgba(255,255,255,0)");
  context.fillStyle = gradient;
  context.fillRect(0, 0, canvas.width, canvas.height);
  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  return texture;
}

function renderLayerCards() {
  const arch = architectures[state.preset];
  dom.layerCards.innerHTML = arch.layers
    .map(
      (layer, index) => `
        <div class="layer-card" data-layer="${index}">
          <span>${layer.name}</span>
          <strong>${layer.count} neurons</strong>
        </div>
      `,
    )
    .join("");
}

function animate(now = 0) {
  animationFrame = requestAnimationFrame(animate);
  frameIndex += 1;
  const elapsed = ((state.paused ? state.pausedAt : now) - state.startedAt) * 0.001;
  const cycle = positiveModulo(elapsed, 20) / 20;
  const palette = getPalette(cycle);
  updateActivations(elapsed, cycle);
  updateGeometry(elapsed, cycle, palette);
  updateHud(cycle);
  moveCamera(elapsed, cycle);
  renderer.render(scene, camera);
}

function updateActivations(elapsed, cycle) {
  const layerFocus = cycle * (architectures[state.preset].layers.length - 1);
  nodes.forEach((node) => {
    const distance = Math.abs(node.layerIndex - layerFocus);
    const wave = Math.max(0, 1 - distance * 0.62);
    const local = 0.5 + Math.sin(elapsed * 2.1 + node.phase + node.index * 0.17) * 0.5;
    node.activation = Math.min(1, 0.08 + wave * 0.78 + local * 0.2);
  });
}

function updateGeometry(elapsed, cycle, palette) {
  const low = hexChannels(palette.low);
  const high = hexChannels(palette.high);
  const pos = nodeGeometry.attributes.position.array;
  const col = nodeGeometry.attributes.color.array;

  nodes.forEach((node, index) => {
    const offset = index * 3;
    const tremor = Math.sin(elapsed * 1.7 + node.phase) * 0.018 * (1 + node.activation);
    pos[offset] = node.base.x + tremor;
    pos[offset + 1] = node.base.y + Math.cos(elapsed * 1.3 + node.phase) * 0.018;
    pos[offset + 2] = node.base.z + Math.sin(elapsed * 1.1 + node.phase) * 0.04;
    writeMixedColor(col, offset, node.tint, high, node.activation * 0.86);
  });
  nodeMaterial.size = cycle > 0.8 ? 0.084 : 0.064 + Math.sin(elapsed * 0.8) * 0.006;
  nodeGeometry.attributes.position.needsUpdate = true;
  nodeGeometry.attributes.color.needsUpdate = true;

  lineMaterial.opacity = cycle > 0.82 ? 0.5 : cycle > 0.24 && cycle < 0.48 ? 0.34 : 0.22;

  if (!links.length) return;

  const pulsePos = pulseGeometry.attributes.position.array;
  const pulseCol = pulseGeometry.attributes.color.array;
  const count = pulsePos.length / 3;
  for (let index = 0; index < count; index += 1) {
    const linkIndex = positiveModulo(index * 11 + Math.floor(elapsed * 34), links.length);
    const link = links[linkIndex];
    const t = positiveModulo(elapsed * (0.38 + link.weight * 0.18) + index / count + link.phase, 1);
    const offset = index * 3;
    pulsePos[offset] = lerp(link.a.base.x, link.b.base.x, t);
    pulsePos[offset + 1] = lerp(link.a.base.y, link.b.base.y, t);
    pulsePos[offset + 2] = lerp(link.a.base.z, link.b.base.z, t);
    writeMixedColor(pulseCol, offset, link.color, [1, 1, 1], link.b.activation * 0.5);
  }
  pulseMaterial.size = cycle > 0.82 ? 0.072 : 0.048;
  pulseGeometry.attributes.position.needsUpdate = true;
  pulseGeometry.attributes.color.needsUpdate = true;

  updateFlares(elapsed, cycle, high);
  updateScanPlane(cycle, high);
}

function updateFlares(elapsed, cycle, high) {
  const flarePos = flareGeometry.attributes.position.array;
  const flareCol = flareGeometry.attributes.color.array;
  const arch = architectures[state.preset];
  const focus = Math.round(cycle * (arch.layers.length - 1));
  const layerNodes = nodes.filter((node) => node.layerIndex === focus);
  const count = flarePos.length / 3;

  for (let index = 0; index < count; index += 1) {
    const node = layerNodes[index % layerNodes.length];
    const angle = elapsed * 1.7 + index * 1.618;
    const radius = 0.08 + (index % 5) * 0.025;
    const offset = index * 3;
    flarePos[offset] = node.base.x + Math.cos(angle) * radius;
    flarePos[offset + 1] = node.base.y + Math.sin(angle * 1.3) * radius;
    flarePos[offset + 2] = node.base.z + 0.08 + Math.sin(angle) * 0.08;
    writeMixedColor(flareCol, offset, high, [1, 0.72, 0.28], cycle > 0.8 ? 0.48 : 0.12);
  }

  flareMaterial.opacity = cycle > 0.8 ? 0.86 : 0.58;
  flareGeometry.attributes.position.needsUpdate = true;
  flareGeometry.attributes.color.needsUpdate = true;
}

function updateScanPlane(cycle, high) {
  const arch = architectures[state.preset];
  const focus = cycle * (arch.layers.length - 1);
  const leftIndex = Math.floor(focus);
  const rightIndex = Math.min(arch.layers.length - 1, leftIndex + 1);
  const left = nodes.find((node) => node.layerIndex === leftIndex);
  const right = nodes.find((node) => node.layerIndex === rightIndex);
  const t = focus - leftIndex;
  const x = left && right ? lerp(left.base.x, right.base.x, t) : 0;

  scanMesh.position.x = x;
  scanMesh.rotation.z = Math.sin(cycle * Math.PI * 2) * 0.06;
  scanMesh.material.opacity = cycle > 0.8 ? 0.92 : 0.72;
  scanMesh.material.color.setRGB(high[0], high[1], high[2]);
}

function updateHud(cycle) {
  const arch = architectures[state.preset];
  const activeLayer = Math.min(arch.layers.length - 1, Math.floor(cycle * arch.layers.length));
  const layer = arch.layers[activeLayer];
  const layerNodes = nodes.filter((node) => node.layerIndex === activeLayer);
  const avg = layerNodes.reduce((sum, node) => sum + node.activation, 0) / layerNodes.length;

  dom.layerName.textContent = layer.name;
  dom.neuronCount.textContent = String(layer.count);
  dom.signalValue.textContent = avg.toFixed(2);
  dom.phaseFill.style.width = `${Math.round(cycle * 100)}%`;

  dom.layerCards.querySelectorAll(".layer-card").forEach((card) => {
    const index = Number(card.dataset.layer);
    const nodesForLayer = nodes.filter((node) => node.layerIndex === index);
    const value = nodesForLayer.reduce((sum, node) => sum + node.activation, 0) / nodesForLayer.length;
    card.style.setProperty("--fill", `${Math.round(value * 100)}%`);
    card.classList.toggle("is-hot", index === activeLayer);
  });
}

function moveCamera(elapsed, cycle) {
  const wide = window.innerWidth > 860;
  group.position.x = wide ? 0.15 : 0;
  group.position.y = wide ? -0.08 : -0.44;
  group.scale.setScalar(wide ? 1.12 : 0.86);
  group.rotation.y = Math.sin(elapsed * 0.13) * 0.035;
  group.rotation.x = Math.cos(elapsed * 0.09) * 0.025;
  camera.position.z = wide ? 8.3 : 9.2;
  camera.position.x = 0;
  camera.lookAt(0, 0, 0);
}

function getPalette(cycle) {
  let active = paletteStops[0];
  for (const stop of paletteStops) {
    if (cycle >= stop.at) active = stop;
  }
  return active;
}

function resize() {
  const width = window.innerWidth;
  const height = Math.max(window.innerHeight, 680);
  setRenderPixelRatio();
  renderer.setSize(width, height, false);
  camera.aspect = width / height;
  camera.updateProjectionMatrix();
}

function setRenderPixelRatio() {
  const cap = window.innerWidth > 860 ? 1.25 : 1.15;
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, cap));
}

function seededRandom(seed) {
  let value = seed % 2147483647;
  if (value <= 0) value += 2147483646;
  return () => {
    value = (value * 16807) % 2147483647;
    return (value - 1) / 2147483646;
  };
}

function writeVector(target, offset, vector) {
  target[offset] = vector.x;
  target[offset + 1] = vector.y;
  target[offset + 2] = vector.z;
}

function writeColor(target, offset, color) {
  target[offset] = color.r;
  target[offset + 1] = color.g;
  target[offset + 2] = color.b;
}

function writeMixedColor(target, offset, a, b, t) {
  target[offset] = lerp(a[0], b[0], t);
  target[offset + 1] = lerp(a[1], b[1], t);
  target[offset + 2] = lerp(a[2], b[2], t);
}

function hexChannels(hex) {
  return [((hex >> 16) & 255) / 255, ((hex >> 8) & 255) / 255, (hex & 255) / 255];
}

function colorForLayer(arch, layerIndex) {
  const colors = arch.colors || segmentColors;
  return colors[layerIndex % colors.length];
}

function normalizedIndex(index, count) {
  return count <= 1 ? 0.5 : index / (count - 1);
}

function lerp(a, b, t) {
  return a + (b - a) * t;
}

function positiveModulo(value, divisor) {
  return ((value % divisor) + divisor) % divisor;
}

window.addEventListener("beforeunload", () => {
  if (animationFrame) cancelAnimationFrame(animationFrame);
});

init();
