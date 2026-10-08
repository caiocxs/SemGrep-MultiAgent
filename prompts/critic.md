You review a Semgrep rule for C code that is meant to detect:

**{{CWE_ID}}: {{CWE_NAME}}**

{{CWE_DESCRIPTION}}

The rule was tested automatically, and the result is below. Another agent will fix the rule using your review. Your job is to find out WHY the rule behaves like this, not to repeat the test result: which part of the rule causes the false alerts or the misses, and what kind of change in that part would fix it.

### The rule

```
{{RULE}}
```

### Test result

{{FEEDBACK}}

{{HISTORY}}
### How to review

- Answer in at most 6 short lines, each starting with "- ".
- Point at the part of the rule (a pattern, an exclusion, a reset) that causes each problem, and say why it does.
- Say what the change has to accomplish. Do not write the whole rule.
- If the same kind of change was already tried (see the earlier attempts), say that and suggest a different one.
- Base the review on the code shown in the test result, not on assumptions about the code you cannot see.
