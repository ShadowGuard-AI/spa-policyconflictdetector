# spa-PolicyConflictDetector
Analyzes two security policy files for conflicting or overlapping rules, and can also validate a configuration against a JSON Schema.

Conflict detection: when both files are policy rule sets, the tool parses each rule's action, resource, and effect (allow or deny, also accepting permit, block, and drop as spellings). Rules are taken from a top level list, or from a `rules`, `policy`, `policies`, `Statement`, or `statements` list, or from a single rule object. A conflict is reported, naming both rules, when a rule in one file and a rule in the other overlap on the same action and the same resource with opposing effects. Conflicts exit 1. A pair with no conflicts prints that no conflicts were found and exits 0.

Schema validation: when the files are not both rule sets, the first file is validated against the second file treated as a JSON Schema. A valid configuration exits 0 and an invalid one exits 1 with the invalid verdict printed by main.

An empty first or second file is a not-performed run: it exits non-zero and prints no valid verdict.

## Install
`git clone https://github.com/ShadowGuard-AI/spa-policyconflictdetector`

## Usage
`python3 main.py CONFIG_OR_POLICY_FILE POLICY_OR_SCHEMA_FILE [--log_level LEVEL]`

## Parameters
- `config_file`: Path to the first file (JSON or YAML): a policy rule set, or a configuration to validate.
- `policy_file`: Path to the second file (JSON or YAML): a policy rule set, or a JSON Schema.
- `-h`: Show help message and exit
- `--log_level`: Set the logging level. Defaults to INFO.

## License
Copyright (c) ShadowGuardAI
