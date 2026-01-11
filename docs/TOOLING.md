# Lafleur Analysis & Triage Workflow

This guide covers the analysis and triage tools that help you monitor fuzzing instances, aggregate campaign results, and manage crash discoveries over time.

-----

## The Data Pipeline Philosophy

Lafleur's analysis tools follow a three-stage pipeline:

```
Instance -> Campaign -> Registry
```

1. **Instance Level** (`lafleur-report`): Monitor the health and progress of a single fuzzing run.
2. **Campaign Level** (`lafleur-campaign`): Aggregate metrics from multiple instances into a unified view.
3. **Registry Level** (`lafleur-triage`): Track crashes historically, link them to GitHub issues, and manage triage status.

Each stage builds on the previous, allowing you to zoom in on individual instances or zoom out to see fleet-wide trends.

-----

## Tool 1: Single Instance Reporting (`lafleur-report`)

The reporter generates a quick health check for a single fuzzing instance.

### Usage

```bash
# Report for current directory
lafleur-report

# Report for a specific instance
lafleur-report /path/to/instance

# Save to file
lafleur-report /path/to/instance > report.txt
```

Or using the module directly:

```bash
python -m lafleur.report /path/to/instance
```

### What It Shows

The report is organized into sections:

| Section | Key Metrics |
|---------|-------------|
| **System** | CPU cores, RAM, Python version, JIT/ASan status |
| **Performance** | Uptime, total executions, speed (exec/s), memory usage |
| **Coverage** | Global edges discovered, global uops, corpus file count |
| **Corpus Evolution** | Tree topology (roots/leaves/depth), sterile rate, top mutations |
| **Crash Digest** | Total crashes, unique fingerprints, table of top 10 crashes |

### Example Output

```
================================================================================
LAFLEUR FUZZING INSTANCE REPORT
================================================================================
Instance Name:  jit_fuzzer_01
Run ID:         a1b2c3d4-...
Hostname:       fuzz-server-01
...

--------------------------------------------------------------------------------
PERFORMANCE
--------------------------------------------------------------------------------
Uptime:         2d 14h 32m
Executions:     1,234,567
Speed:          142.50 exec/s
Memory (RSS):   512.30 MB

--------------------------------------------------------------------------------
CRASH DIGEST
--------------------------------------------------------------------------------
Total Crashes:       47
Unique Fingerprints: 12

 Count | First Seen          | Fingerprint                    | Sample Repro
--------------------------------------------------------------------------------
    15 | 2026-01-09 14:23:00 | Assert:_Py_uop_eval:frame->... | crashes/crash_.../reproduce.sh
     8 | 2026-01-09 16:45:12 | SEGV:_PyObject_GetAttr:0x0     | crashes/crash_.../reproduce.sh
...
```

### When to Use

- **Quick health check**: Is my fuzzer still running? How fast is it going?
- **Coverage progress**: Has this instance found new edges recently?
- **Crash triage prep**: What unique crashes has this instance found?

-----

## Tool 2: Campaign Management (`lafleur-campaign`)

The campaign aggregator combines metrics from multiple instances, deduplicates crashes, and produces fleet-wide summaries.

### Usage

```bash
# Aggregate all instances under runs/
lafleur-campaign runs/

# Generate HTML dashboard with registry enrichment
lafleur-campaign runs/ --html report.html --registry crashes.db

# Text-only output
lafleur-campaign runs/
```

Or using the module directly:

```bash
python -m lafleur.campaign runs/ --html report.html --registry crashes.db
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `campaign_dir` | Directory containing instance subdirectories |
| `--html FILE` | Generate an interactive HTML report |
| `--registry DB` | Enrich crashes with triage status from the registry database |

### Understanding the Output

#### Fleet Summary

```
================================================================================
LAFLEUR CAMPAIGN SUMMARY
================================================================================
Campaign Root:     /data/fuzzing/runs
Instances Found:   24
Instances Active:  22 (91.7%)
...
```

#### Key Metrics Explained

| Metric | Description |
|--------|-------------|
| **Fleet Speed** | Combined execution rate across all active instances (exec/s) |
| **Total Executions** | Sum of all mutations attempted across the campaign |
| **Global Coverage** | Union of all edges discovered (deduplicated) |
| **Unique Crashes** | Fingerprints found across all instances (deduplicated) |

#### Instance Leaderboard

The leaderboard ranks instances by performance:

```
Instance Name                | Status  |    Speed |  Coverage | Crashes | Corpus
--------------------------------------------------------------------------------
jit_fuzzer_01                | Running |   156.20 |    12,456 |      15 |   1,234
jit_fuzzer_02                | Running |   142.80 |    11,890 |      12 |   1,156
...
```

#### Global Crash Table

Shows all unique crashes across the campaign:

```
Fingerprint                     | Count | Status     | Instances           | First Found
--------------------------------------------------------------------------------
Assert:_Py_uop_eval:frame->...  |    47 | KNOWN #128 | fuzzer_01, fuzzer_02| 2026-01-09
SEGV:_PyObject_GetAttr:0x0      |    12 | NEW        | fuzzer_03           | 2026-01-10
```

### The HTML Report

When using `--html`, you get an interactive dashboard with:

- **KPI Cards**: At-a-glance summary of instances, speed, coverage, crashes
- **Instance Leaderboard**: With visual "data bars" showing relative performance
- **Sortable Crash Table**: Click column headers to sort by count, status, or date
- **Status Badges**: Color-coded labels (NEW, KNOWN, REGRESSION, NOISE)
- **Direct Links**: When using `--registry`, crashes link to their GitHub issues

The HTML report is fully self-contained (embedded CSS/JS, no external dependencies) and works offline.

### Registry Integration

When you provide `--registry crashes.db`, crashes are enriched with historical data:

| Status Label | Meaning |
|--------------|---------|
| **NEW** | Never seen before in the registry |
| **KNOWN** | Already linked to an open GitHub issue |
| **REGRESSION** | Linked to a previously FIXED issue (bug returned!) |
| **NOISE** | Marked as IGNORED or WONTFIX in triage |

This helps you quickly identify which crashes need attention and which are already being tracked.

-----

## Tool 3: Historical Triage (`lafleur-triage`)

The triage tool provides a SQLite-based registry for tracking crashes across campaigns, linking them to GitHub issues, and managing their lifecycle.

### Database Schema

The registry maintains three tables:

| Table | Purpose |
|-------|---------|
| `reported_issues` | GitHub issues you've filed for crashes |
| `crashes` | Unique crash fingerprints and their triage status |
| `sightings` | Individual occurrences of crashes across runs |

### Subcommands

#### Importing Crashes

Scan a campaign directory and import all crash sightings:

```bash
lafleur-triage import runs/

# Use a different database
lafleur-triage --db my_crashes.db import runs/
```

Output:
```
[+] Found 24 instance(s) to import
  [+] jit_fuzzer_01: Imported 15 sightings (3 duplicates skipped)
  [+] jit_fuzzer_02: Imported 12 sightings (2 duplicates skipped)
...
[+] Total: 127 sightings imported, 23 duplicates skipped

[+] Registry now contains:
    45 unique crashes
    150 total sightings
    24 unique instances
```

#### Interactive Triage

The "Tinder for Crashes" loop: review each NEW crash and decide its fate:

```bash
lafleur-triage interactive
```

For each crash, you'll see:

```
----------------------------------------------------------------
CRASH [1/12]: Assert:_Py_uop_eval:frame->previous != NULL
First Seen: 2026-01-09T14:23:00 | Total Sightings: 47
Notes: Possibly related to frame unwinding
----------------------------------------------------------------

Action? [R]eport / [I]gnore / [M]ark Fixed / [N]ote / [S]kip / [Q]uit >
```

| Action | Effect |
|--------|--------|
| **R**eport | Link to a GitHub issue number, mark as REPORTED |
| **I**gnore | Mark as IGNORED (noise, not a real bug) |
| **M**ark Fixed | Mark as FIXED (issue was resolved) |
| **N**ote | Add a note without changing status |
| **S**kip | Move to next crash without changing anything |
| **Q**uit | Exit the triage loop |

#### Reviewing Triaged Crashes

Audit and correct previous triage decisions:

```bash
# Review all non-NEW crashes
lafleur-triage review

# Review only crashes with specific status
lafleur-triage review --status REPORTED
lafleur-triage review --status IGNORED
```

The review interface allows you to:

| Action | Effect |
|--------|--------|
| **L**ink issue | Link (or re-link) to a different issue number |
| **U**nlink | Remove the crash-to-issue association |
| **S**tatus | Change triage status (NEW, TRIAGED, REPORTED, IGNORED, FIXED) |
| **N**ote | Add or update notes |
| **K**eep | Skip without changes |
| **Q**uit | Exit the review loop |

#### Recording GitHub Issues

Interactive wizard to record a new GitHub issue:

```bash
lafleur-triage record-issue
```

This prompts for issue details (number, title, URL, CPython version, etc.) and optionally links it to a crash fingerprint.

#### Viewing Status

```bash
# Show registry statistics
lafleur-triage status

# List all crashes
lafleur-triage list

# Filter by triage status
lafleur-triage list --status NEW
lafleur-triage list --status REPORTED

# Show details for a specific crash
lafleur-triage show "Assert:_Py_uop_eval:frame->previous"
```

#### Knowledge Base Export/Import

Share your known issues database with the team:

```bash
# Export to JSON
lafleur-triage export-issues known_issues.json

# Import from JSON (e.g., from another machine or teammate)
lafleur-triage import-issues known_issues.json
```

The JSON file contains all recorded GitHub issues and can be committed to your repository as a shared knowledge base.

-----

## Workflow Example: A Day in the Life

Here's a typical workflow for managing a multi-instance fuzzing campaign:

### 1. Run Fuzzers Overnight

Start multiple instances across your fleet:

```bash
# On each machine
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded
```

### 2. Morning: Generate Campaign Report

Aggregate results from all instances:

```bash
lafleur-campaign /mnt/shared/fuzzing_runs/ \
    --html campaign_report.html \
    --registry crashes.db
```

Open `campaign_report.html` in your browser to see:
- How many instances are still running
- Combined speed and coverage progress
- New crashes discovered overnight

### 3. Import Results to Registry

Update the crash registry with new sightings:

```bash
lafleur-triage import /mnt/shared/fuzzing_runs/
```

### 4. Triage New Crashes

Review crashes that need attention:

```bash
lafleur-triage interactive
```

For each crash:
1. Investigate the reproduce script
2. Determine if it's a real bug or noise
3. File a GitHub issue if it's new and valid
4. Link the crash to the issue

### 5. Check for Regressions

The campaign report highlights crashes with status **REGRESSION**. These are crashes linked to issues that were marked FIXED but are now appearing again.

Regenerate the report after triage:

```bash
lafleur-campaign /mnt/shared/fuzzing_runs/ \
    --html campaign_report.html \
    --registry crashes.db
```

Look for the red "REGRESSION" badges in the crash table.

### 6. Share Knowledge Base

Export your triage decisions for the team:

```bash
lafleur-triage export-issues known_issues.json
git add known_issues.json
git commit -m "Update known issues database"
```

-----

## Quick Reference

| Task | Command |
|------|---------|
| Check single instance health | `lafleur-report /path/to/instance` |
| Generate campaign dashboard | `lafleur-campaign runs/ --html report.html` |
| Import crashes to registry | `lafleur-triage import runs/` |
| Triage new crashes | `lafleur-triage interactive` |
| Review past decisions | `lafleur-triage review` |
| Check registry status | `lafleur-triage status` |
| Export known issues | `lafleur-triage export-issues known_issues.json` |
