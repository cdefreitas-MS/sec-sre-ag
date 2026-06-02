# sec-sre-ag — SRE Agent Custom Skills

Repository of supporting files (scripts, data, configurations) for the custom skills
of the Azure SRE Agent `sec-sre-ag`.

## Structure

```
sec-sre-ag/
├── shared/                    ← Scripts shared across multiple skills
├── <skill-name>/              ← Scripts and data to materialize for each skill
└── .builder/                  ← Reference copies of SKILL.md files and LLM docs
    └── <skill-name>/             (the authoritative version is in the Builder)
```

### Convention

| Location | Content | Read by |
|---|---|---|
| `<skill>/` (root) | `.py` scripts, `.json` / `.yaml` data files read by scripts | Python interpreter |
| `shared/` | Scripts shared across skills | Python interpreter |
| `.builder/<skill>/` | SKILL.md, reference docs, KQL queries, svg-widgets.yaml | LLM via `read_skill_file` API |

### Builder-only Files

The files in `.builder/` are **backup / reference copies**. The authoritative version
of all SKILL.md and LLM instruction files is the one in the agent's **Builder**
(SRE Agent portal → Builder → Skills).

### Secrets

API tokens and environment parameters are NOT in the repo.
See `shared/.env.example` for the template of required environment variables.
