# Time-split test set

This directory holds the rule for the time-split test set and, once it has
been selected, its manifest. Nothing else. No advisory published on or after
2026-10-01 has been queried, counted, fetched or scanned for this set, and
nobody should do so before the detection rules for the next release are
frozen.

The headline number for a release comes from this set. The v1 held-out set
and the development set have both been looked at; this one has not.

## Rule

The rule is the v1 rule (`benchmarks/heldout/selection.py`) with three
changes, all in code (`timesplit_rule`, `cli.timesplit_problems`):

1. **Window.** Reviewed `pip` and `npm` advisories published from 2026-10-01
   (or a later `--since`) up to and including the freeze date `--until`. The
   API's date filter is re-checked on every advisory's `published_at`.
   `--until` must be before today (UTC), so the window is closed and cannot
   gain advisories after selection.
2. **Exclusions.** Every advisory that the v1 or development selection
   examined is skipped, whether it became a case or was dropped, as is any
   advisory that shares a CVE id with one of them. A file and fix commit that
   is already a v1 or development case is never a case again.
3. **Sampling.** Candidates are ordered by SHA-256 of `"timesplit:"` plus the
   upper-cased GHSA id, and taken until 200 `pip` and 150 `npm` cases are
   reached or the candidates run out.

The CWE list, the fix-commit rule, the file rules and the 5-file localized-fix
cap are the v1 ones, unchanged.

## Freeze guard

```bash
python benchmarks/heldout/run.py select --set timesplit \
    --until YYYY-MM-DD --rules-frozen-at <full commit sha>
```

`select --set timesplit` refuses to run, before it makes any request, unless:

- `--rules-frozen-at` is a full 40-character commit SHA in this repository
  (not a branch or tag, which can move);
- `src/nephilex` in the checkout is identical to that commit, with no
  untracked files;
- `--until` is a valid date on or after the start and before today (UTC);
- the v1 and development manifests it excludes exist;
- no time-split manifest exists yet (the set is selected once).

The manifest records the frozen commit, the commit of the harness that ran the
selection and the time of the acknowledgement (`freeze`). `scan --set
timesplit` refuses to run when `src/nephilex` differs from the frozen commit,
so the published score is the score of the frozen rules.

## After it is scored

Once a time-split set's per-case results are published, it has been seen and
becomes development data. The next release needs a new time-split set with
`--since` set to the day after the previous `--until`. That takes a code
change, committed before selection: a new set entry in `cli.SETS` whose
exclusions in `cli.PRIOR` include the previous time-split set.
