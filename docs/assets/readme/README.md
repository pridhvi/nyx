# README Media Assets

These screenshots are generated from the local vulnerable fixture and a temporary Nyx session.

Regenerate from the repository root:

```sh
./scripts/readme-media.sh
```

The script uses only localhost fixture data and does not require a real target, API key, or LLM endpoint.
It seeds a small deterministic demo LLM history row so the Analyst screenshot is not model-dependent.

GIF generation is optional. If ImageMagick is installed as `magick` or `convert`, or Python has Pillow available, the script also writes `nyx-demo-flow.gif`.
