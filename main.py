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
        description="Analyzes configuration files against security policies to identify conflicts or violations."
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
    try:
        jsonschema.validate(instance=config_data, schema=policy_data)
        return True
    except jsonschema.exceptions.ValidationError as e:
        logging.error(f"Configuration validation failed: {e}")
        raise
    except jsonschema.exceptions.SchemaError as e:
        logging.error(f"Invalid JSON schema: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred during validation: {e}")
        raise


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

        # Validate the configuration against the policy.
        if validate_config(config_data, policy_data):
            logging.info("Configuration is valid according to the policy.")
            print("Configuration is valid according to the policy.")
        else:
            logging.warning("Configuration is invalid according to the policy.")
            print("Configuration is invalid according to the policy.")

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