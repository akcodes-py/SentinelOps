# Residual risk (PDR §6.3.10)

Built from the held-out and adaptive runs, never from the development split. Every case
with a success rate above zero appears in `results/residual_risk.json` with its OWASP
reference, the checkpoint that should have caught it, why it was missed, and whether it
is scheduled for a fix or accepted as risk with a justification.

Run `python scripts/run_evaluation.py --repeats 2` to regenerate. The final report must
report every target in §3.1 as measured, whether or not it was met.
