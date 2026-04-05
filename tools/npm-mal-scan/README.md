# npm-mal-scan (npm-project)

This folder should contain the **npm-mal-scan** package (the `npm-project` repo): the Node CLI that scans npm packages for malicious behavior and supply-chain signals.

## Option A — Sibling clone (no copy)

If `npm-project` sits next to this repo (e.g. `GitHub/npm-project` and `GitHub/ExtRisk-push`), nothing is required here. The Python helper `src/npm_mal_scan_runner.py` resolves `../npm-project` automatically.

## Option B — Vendored path `tools/npm-mal-scan`

Use any of:

- **Git submodule** (if `npm-project` has a remote):  
  `git submodule add <your-npm-project-url> tools/npm-mal-scan`
- **Directory junction (Windows)** from repo root:  
  `cmd /c mklink /J tools\npm-mal-scan ..\npm-project`
- **Symlink (Unix):**  
  `ln -s ../../npm-project tools/npm-mal-scan`

## Build once

```bash
cd tools/npm-mal-scan   # or cd ../npm-project
npm install
npm run build
```

## Run

From **ExtRisk-push** repo root:

```bash
python src/npm_mal_scan_runner.py --help
python src/npm_mal_scan_runner.py <package>@<version>   # same args as npm-mal-scan CLI
```

Or, if this directory is populated:

```bash
npm run mal-scan -- --help
```
