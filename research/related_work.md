# Related work and attribution (reviewed starting references)

This is a selected scientific/technical reading list, **not** evidence that NTK has attained the same benchmark numbers as the referenced systems.

## IRIS: neuro-symbolic vulnerability discovery

- Ziyang Li, Saikat Dutta, Mayur Naik. **IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities**. International Conference on Learning Representations (ICLR), 2025. https://proceedings.iclr.cc/paper_files/paper/2025/hash/582d4e27fa24168f3af1f4582655034b-Abstract-Conference.html
- Upstream code: https://github.com/iris-sast/iris (MIT-licensed upstream source; retain its notices when redistributing code).

The IRIS paper studies a neuro-symbolic combination of LLM-derived security specifications with static analysis and whole-repository vulnerability detection. The **current NTK production implementation is inspired by IRIS but is not the same code path**: it uses OpenGrep candidates and an OpenJDK 17 JavacTask AST implementation with intra-procedural evidence. Do not claim IRIS paper's results as NTK measurements.

## Qwen2.5-Coder family

- Binyuan Hui et al. **Qwen2.5-Coder Technical Report**. arXiv:2409.12186 (2024). https://arxiv.org/abs/2409.12186
- Current model family: https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct

The report provides background on code-specialized pretrained model families; it does not validate the particular **NTK EO06 LoRA checkpoint** or the four-class security-role task. Those require local, locked-corpus evaluations.

## OpenGrep OSS engine

- Engine, rule syntax, license and releases: https://github.com/opengrep/opengrep

OpenGrep is an open-source SAST engine, a Semgrep fork with an LGPL-2.1 licensing statement in the public repository. Treat its documented engine capabilities as background only; the deployed NTK capabilities are bounded by the **actual version, four-CWE ruleset and integration path**.

## Research attribution rule

Separate **(1) upstream scientific contribution**, **(2) prior NTK experiments**, **(3) the current implementation**, and **(4) current experimental evidence**. Preserve all four distinctions in the thesis and README. Bibliographic citations are references, not substitute benchmarks.
