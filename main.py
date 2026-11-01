import argparse
import json
import logging
import sys

import jsonschema
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse():
    """
    Sets up the argument parser for the tool.
    """
    parser = argparse.ArgumentParser(
        description="Detects conflicts between two policy files, and validates the first against the second treated as a JSON Schema when it is a schema."
    )
    parser.add_argument(
        "config_file",
        help="Path to the configuration file (JSON or YAML).",
        type=str,
    )
    parser.add_argument(
        "policy_file",
        help="Path to the security policy file (JSON schema or YAML rules).",
        type=str,
    )
    parser.add_argument(
        "--log_level",
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to INFO.",
        default="INFO",
        type=str.upper,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )

    return parser


def load_config(config_file):
    """
    Loads a configuration file (JSON or YAML).

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        dict: The configuration data as a dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the config file format is not supported.
    """
    try:
        with open(config_file, "r") as f:
            # The extension decides the parser and the check is case
            # sensitive, so a file named CONFIG.JSON is rejected as an
            # unsupported format even though its contents would parse.
            if config_file.endswith(".json"):
                config_data = json.load(f)
            elif config_file.endswith(".yaml") or config_file.endswith(".yml"):
                config_data = yaml.safe_load(f)
            else:
                raise ValueError(
                    "Unsupported configuration file format. Use JSON or YAML."
                )
        return config_data
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON in {config_file}: {e}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error decoding YAML in {config_file}: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def load_policy(policy_file):
    """
    Loads a security policy file (JSON schema or YAML rules).

    Args:
        policy_file (str): Path to the policy file.

    Returns:
        dict: The policy data as a dictionary.

    Raises:
        FileNotFoundError: If the policy file does not exist.
        ValueError: If the policy file format is not supported.
    """
    try:
        with open(policy_file, "r") as f:
            if policy_file.endswith(".json"):
                policy_data = json.load(f)
            elif policy_file.endswith(".yaml") or policy_file.endswith(".yml"):
                policy_data = yaml.safe_load(f)
            else:
                raise ValueError("Unsupported policy file format. Use JSON or YAML.")
        return policy_data
    except FileNotFoundError:
        logging.error(f"Policy file not found: {policy_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON in {policy_file}: {e}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error decoding YAML in {policy_file}: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def validate_config(config_data, policy_data):
    """
    Validates a configuration against a security policy.

    Args:
        config_data (dict): The configuration data.
        policy_data (dict): The security policy data (JSON schema).

    Returns:
        bool: True if the configuration is valid, False otherwise.

    Raises:
        jsonschema.exceptions.ValidationError: If the configuration is invalid
            according to the schema.
        jsonschema.exceptions.SchemaError: If the schema itself is invalid.
        Exception: For any other unexpected errors during validation.
    """
    # This function never returns False. Validation either passes or
    # raises, so the invalid branch in main is dead code and every
    # failure arrives there as an exception instead.
    # The policy is always used as a JSON Schema, whatever form the
    # file took. A YAML rules file parses fine in load_policy and then
    # fails here as a malformed schema, not as a list of rules.
    try:
        jsonschema.validate(instance=config_data, schema=policy_data)
        return True
    except jsonschema.exceptions.ValidationError as e:
        logging.error(f"Configuration validation failed: {e}")
        return False
    except jsonschema.exceptions.SchemaError as e:
        logging.error(f"Invalid JSON schema: {e}")
        raise


def extract_rules(data):
    """Return a list of rule dicts from common policy shapes, or None."""
    if isinstance(data, dict):
        for key in ("rules", "policy", "policies", "Statement", "statements"):
            if key in data and isinstance(data[key], list):
                return data[key]
        if any(k in data for k in ("action", "Action", "effect", "Effect", "resource", "Resource")):
            return [data]
        return None
    if isinstance(data, list):
        return data
    return None


def rule_fields(rule):
    if not isinstance(rule, dict):
        return None
    def pick(*names):
        for n in names:
            if n in rule:
                v = rule[n]
                return v[0] if isinstance(v, list) and v else v
        return None
    action = pick("action", "Action")
    resource = pick("resource", "Resource")
    effect = pick("effect", "Effect", "decision")
    name = pick("name", "id", "Name", "Id") or "unnamed"
    if action is None or resource is None or effect is None:
        return None
    effect_norm = str(effect).strip().lower()
    if effect_norm in ("allow", "permit"):
        effect_norm = "allow"
    elif effect_norm in ("deny", "block", "drop"):
        effect_norm = "deny"
    else:
        return None
    return {"name": str(name), "action": str(action), "resource": str(resource), "effect": effect_norm}


def detect_conflicts(rules_a, rules_b):
    conflicts = []
    fa = [r for r in (rule_fields(x) for x in rules_a) if r]
    fb = [r for r in (rule_fields(x) for x in rules_b) if r]
    for a in fa:
        for b in fb:
            if a["action"] == b["action"] and a["resource"] == b["resource"] and a["effect"] != b["effect"]:
                conflicts.append((a, b))
    return conflicts, len(fa), len(fb)



def main():
    """
    Main function to execute the security policy validation.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set the logging level based on the CLI argument.
    logging.getLogger().setLevel(args.log_level)

    try:
        # Load configuration and policy files.
        config_data = load_config(args.config_file)
        policy_data = load_policy(args.policy_file)

        if config_data is None or config_data == {} or config_data == []:
            logging.error("First file is empty: nothing was checked.")
            sys.exit(2)
        if policy_data is None or policy_data == {} or policy_data == []:
            logging.error("Second file is empty: nothing was checked.")
            sys.exit(2)
        rules_a = extract_rules(config_data)
        rules_b = extract_rules(policy_data)
        if rules_a is not None and rules_b is not None:
            conflicts, count_a, count_b = detect_conflicts(rules_a, rules_b)
            if count_a == 0 or count_b == 0:
                logging.error("Policy files held no usable rules (need action, resource, and effect): conflict check not performed.")
                sys.exit(2)
            if conflicts:
                for a, b in conflicts:
                    print(f"Conflict: rule '{a['name']}' ({a['effect']}) and rule '{b['name']}' ({b['effect']}) overlap on action {a['action']} and resource {a['resource']}.")
                sys.exit(1)
            print("No conflicts found between the two policy files.")
            return
        if validate_config(config_data, policy_data):
            logging.info("Configuration is valid according to the policy.")
            print("Configuration is valid according to the policy.")
        else:
            logging.warning("Configuration is invalid according to the policy.")
            print("Configuration is invalid according to the policy.")
            sys.exit(1)

    except FileNotFoundError:
        logging.error("One or more files not found. Exiting.")
        sys.exit(1)
    except ValueError as e:
        logging.error(f"Invalid file format or content: {e}")
        sys.exit(1)
    except jsonschema.exceptions.ValidationError:
        logging.error("Validation error occurred. Check the policy and configuration files.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()