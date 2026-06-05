# Neural Cinema

An interactive browser demo that turns neural-network-style signal flow into a real-time visual instrument.

It is a visual metaphor, not model introspection. The demo is designed for explaining and exploring how different network topologies can feel when information moves through them.

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

Open `index.html` in a browser.

The demo uses CDN builds of Three.js and Lucide, so an internet connection is required the first time it loads.

## Deploy

This repository is ready for GitHub Pages. Serve it from the `main` branch root.
