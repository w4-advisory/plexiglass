from importlib.resources import files
import typer
from .experiment import Experiment
from .core.scanner import Scanner, load_dataset_config
from InquirerPy import inquirer
import json, os
from typing import List
from getpass import getpass
from typing_extensions import Annotated

app = typer.Typer()

def _load_options() -> dict:
    """Load available model options from options.json.

    Returns:
        dict: Available model options.
    """
    with files("plexiglass").joinpath("config/options.json").open() as f:
        options_json = json.load(f)
        return options_json

def config_llm(metrics: list) -> Experiment:
    """Configure LLM experiment.

    Args:
        metrics (list): List of metrics to evaluate in the experiment.

    Returns:
        Experiment: Experiment object.
    """
    config = _load_options()

    ## select provider
    provider = inquirer.select(
        message="Select your provider:",
        choices=list(config.keys()),
    ).execute()

    ## select model
    model = inquirer.select(
        message="Select your model:",
        choices=config[provider]["model_list"],
    ).execute()

    ## export api key
    api_key = getpass("Please provide your API key: ")
    os.environ[config[provider]["api_key_var_name"]] = api_key

    typer.echo(f"Selected provider and model: {provider}, {model}")
    return Experiment(model_type=provider, model_name=model, metrics=metrics)

def run_llm(experiment: Experiment) -> None:
    """Execute LLM experiment.

    Args:
        experiment (Experiment): Experiment object.
    """
    experiment.conversation()


def config_scan(metrics: list) -> Scanner:
    """Configure LLM scan.

    Args:
        metrics (list): List of metrics to evaluate in the scan.

    Returns:
        Scanner: Scanner object.
    """
    config = _load_options()
    datasets_config = load_dataset_config()

    ## select provider
    provider = inquirer.select(
        message="Select your provider:",
        choices=list(config.keys()),
    ).execute()

    ## select model
    model = inquirer.select(
        message="Select your model:",
        choices=config[provider]["model_list"],
    ).execute()

    ## export api key
    api_key = getpass("Please provide your API key: ")
    os.environ[config[provider]["api_key_var_name"]] = api_key

    typer.echo(f"Selected provider and model: {provider}, {model}")
    return Scanner(model_type=provider, model_name=model, metrics=metrics), datasets_config


def run_scan(scanner: Scanner, datasets_config: dict) -> None:
    """Execute LLM security scan.

    Args:
        scanner (Scanner): Scanner object.
        datasets_config (dict): Available datasets configuration.
    """
    ## select dataset
    dataset = inquirer.select(
        message="Select benchmark dataset:",
        choices=list(datasets_config.keys()),
    ).execute()

    ## select sample size
    sample_size = inquirer.number(
        message="Enter sample size (number of prompts to test):",
        default=50,
        min_allowed=1,
        max_allowed=1000,
    ).execute()

    typer.echo(f"\nStarting scan with dataset: {dataset}")
    results = scanner.scan(dataset, sample_size=int(sample_size))

    typer.echo("\n--- Scan Results ---")
    print(results)

    summary = scanner.get_summary()
    typer.echo("\n--- Summary ---")
    for key, value in summary.items():
        if isinstance(value, float):
            typer.echo(f"{key}: {value:.4f}")
        else:
            typer.echo(f"{key}: {value}")


@app.command()
def main(mode: Annotated[str, typer.Option(help="Mode to run. Choose from: llm-chat, llm-scan")], 
         metrics: Annotated[List[str], typer.Option(help="Metrics to monitor. Choose from: toxicity")]):
    """
    This application performs different tasks based on the selected mode.
    """
    
    if mode.lower() == "llm-chat":
        experiment = config_llm(metrics)
        run_llm(experiment)
    elif mode.lower() == "llm-scan":
        scanner, datasets_config = config_scan(metrics)
        run_scan(scanner, datasets_config)
    else:
        typer.echo("Invalid mode selected.")