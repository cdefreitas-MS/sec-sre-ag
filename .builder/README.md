# ⚠️ Copie di riferimento — NON autoritativo

I file in questa cartella sono **copie di backup** dei file SKILL.md e dei documenti
di istruzione LLM definiti nel Builder dell'agente.

**La versione autoritativa è nel Builder** (portale SRE Agent → Builder → Skills).

Quando modifichi uno skill:
1. Modifica PRIMA nel Builder
2. Poi aggiorna la copia qui per mantenerla allineata
3. NON fare il contrario (modifica qui sperando che l'agente la legga da codeRefs)

L'agente legge sempre i file skill dal Builder tramite l'API `read_skill_file`.
I file in `codeRefs/` sono usati dall'agente solo come contesto di codice/knowledge,
MAI come sorgente skill.
