# Skill Submission Test Cases

Use `evals/trigger-cases.json`. The dataset contains nine positive cases and six negative cases. Run each case repeatedly against the exact target model/skill bundle and record invoked skill, model ID, bundle hash, latency, tokens, and variance. Any implicit invocation is a failure because all skills set `allow_implicit_invocation: false`; positive cases assume explicit `$skill-name` routing or equivalent user selection.
