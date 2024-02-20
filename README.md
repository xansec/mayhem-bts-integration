# bts_export.py

Uses the API to export one or more Mayhem for API defects to a BTS.
```
usage: bts_export.py [-h] --workspace WORKSPACE --project PROJECT --target TARGET --bts BTS [--defect DEFECT] [--run RUN] [--bts-config BTS_CONFIG] [--mayhem-config MAYHEM_CONFIG] [--use-pass] [--log LOG] [--insecure] [--dry-run]

optional arguments:
  -h, --help            show this help message and exit
  --workspace WORKSPACE
                        The workspace for the project
  --project PROJECT     The name of the project
  --target TARGET       The name of the target
  --bts BTS             The type of BTS you want to export to (choices: 'jira', 'gitlab')
  --defect DEFECT       The defect number to export (exports a single defect)
  --run RUN             The run number to export (exports all defects in a run)
  --bts-config BTS_CONFIG
                        The BTS configuration file (defaults to 'bts.config')
  --mayhem-config MAYHEM_CONFIG
                        The Mayhem configuration file (defaults to 'mayhem.config')
  --use-pass            Use UNIX password store instead of hardcoded tokens
  --log LOG             Log level (choose from debug, info, warning, error and critical)
  --insecure            Disable SSL verification
  --dry-run             Dry run

example: python bts_export.py --workspace myworkspace --project myproject --target mytarget --bts jira --defect 11590 --use-pass
Issue SM-42 created.
Link to newly created JIRA issue: https://my.atlassian.net/rest/api/2/issue/123
```

