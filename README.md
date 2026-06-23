# Neural Cinema

[![Static check](https://github.com/majiayu000/neural-cinema/actions/workflows/check.yml/badge.svg)](https://github.com/majiayu000/neural-cinema/actions/workflows/check.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An interactive browser demo that turns neural-network-style signal flow into a real-time visual instrument.

It is a visual metaphor, not model introspection. The demo is designed for explaining and exploring how different network topologies can feel when information moves through them.

Live demo: <https://majiayu000.github.io/neural-cinema/>

## Modes

- `Agent Decision MLP`: a policy bottleneck that fans out into tool, risk, and action gates.
- `Vision Feature Mixer`: local receptive-field style feature extraction from pixels to class.
- `Language Router`: memory and attention skip links flowing into token selection.

## Controls

- Pause or resume the animation.
- Reseed the network to generate a new layout.
- Change connection density.
- Switch between the three topology presets.

## Run Locally

Open `index.html` in a browser, or serve the directory locally:

```bash
python3 -m http.server 8000
```

Then open <http://localhost:8000/>.

There is no build step. The demo requires a modern WebGL-capable browser and
uses version-pinned CDN builds of Three.js and Lucide, so an internet connection
is required the first time it loads.

## Verify

```bash
python3 scripts/check_static_site.py
node --check app.js
```

## Deploy

This repository is ready for GitHub Pages. Serve it from the `main` branch root.
