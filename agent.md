# Agent Instructions

- Run all repository tests with the conda `paddle` environment.
- Prefer the direct interpreter path instead of `conda run`:
  `C:\Users\vis\.conda\envs\paddle\python.exe -m pytest ...`
- If a test dependency is missing, install it into the same `paddle` environment:
  `C:\Users\vis\.conda\envs\paddle\python.exe -m pip install <package>`
- Do not switch test execution to `base`, `pytorch`, `.venv-pytorch`, or other environments unless the user explicitly asks.
