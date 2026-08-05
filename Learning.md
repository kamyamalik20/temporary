# Learning Log

A running record of bugs/issues hit in this project, what caused them, and
how they were fixed — so the same mistake isn't repeated later.

---

## 2026-08-05 — Scanned files showing "date: None" and "size: 0B"

### Symptom
When looking at scanned file results, individual entries displayed the
date as `None` (e.g. "None days" / blank date) and the size as `0B`, even
for files that were clearly non-empty and had a real modification time.

### Investigation
Looked at `app/files.py`'s `scan()` function — the function that actually
walks the filesystem and builds each file's record. Before the fix, each
result dict only contained:

```python
{
    "path": filepath,
    "size_mb": size_mb,
    "age_days": age_days,
    "type": classify_type(filepath),
}
```

Notice what's **missing**: there is no `date` key and no `size` key —
only `size_mb` and `age_days`. `age_days` is a *duration* (an integer,
e.g. `42`), not a date at all.

### Root cause
Anything downstream (a dashboard, a report generator, a template) that
tried to read `file.get("date")` or `file.get("size")` — instead of the
exact keys `age_days` / `size_mb` — would silently get back `None` / not
found. Python's `dict.get()` doesn't raise an error on a missing key, it
just returns `None` (or whatever default was passed, e.g. `0`). That's
exactly the "None date / 0B size" symptom: not a calculation bug, but a
**key-name mismatch between producer and consumer** that nothing ever
surfaced as an error.

This is a common failure mode in loosely-typed JSON pipelines: the
producer changes or was never fully aligned with what the consumer
expects, and because dict lookups fail silently, the mismatch shows up as
"wrong values" rather than a crash — much harder to trace.

### Fix
`app/files.py` now emits an unambiguous, redundant set of fields on every
scanned entry:

```python
{
    "path": filepath,
    "size_mb": size_mb,
    "size_bytes": st.st_size,
    "age_days": age_days,
    "modified_date": "YYYY-MM-DD HH:MM:SS",   # explicit, always present
    "type": classify_type(filepath),
    "owner_uid": st.st_uid,                    # also needed for the new
                                                # UID-ownership rule
}
```

The top-level scan output also now *always* includes `scanned_at` (it
existed in the code before, but a `files.json` sample we found on disk was
missing it entirely — likely produced by an older version of the script,
or hand-edited — which caused the same class of problem one level up).

Also fixed while in this function: the old code called `os.lstat()` and
then separately called `os.path.islink()` — two syscalls, with a small
race window between them. It now checks `stat.S_ISLNK()` on the single
`lstat()` result already in hand, which is both faster and race-free.

### Prevention going forward
- **If a bug looks like "wrong value" rather than a crash, suspect a
  silent `dict.get()` miss before suspecting the math.** Grep both sides
  (producer and consumer) for the exact key names being used.
- When adding a new consumer of `files.json` / the `/scan` API response,
  use the field names above exactly — `size_mb`, `size_bytes`, `age_days`,
  `modified_date`, `owner_uid`, `type`, `path`. Don't invent aliases like
  `date` or `size` in the consumer; if a friendlier name is genuinely
  needed, add it explicitly to the producer (this file) so it can never
  silently go missing.
- If this exact symptom (`None`/`0B`) shows up again in a specific
  dashboard or report file, that file is doing its own key lookup — it
  needs to be checked directly, since it isn't part of this repo's
  uploaded set as of this writing.

---

## Template for future entries

```
## YYYY-MM-DD — <short symptom description>

### Symptom
### Investigation
### Root cause
### Fix
### Prevention going forward
```
