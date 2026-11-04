from importlib.resources import files
from datasets import load_dataset
from ..model import Model
from .evaluate import evaluate
from langchain.chains import ConversationChain
from langchain.chains.conversation.memory import ConversationBufferWindowMemory
import pandas as pd
import json
from tqdm import tqdm


def load_dataset_config() -> dict:
    """Load available dataset options from datasets.json.

    Returns:
        dict: Available dataset configurations.
    """
    with files("plexiglass").joinpath("config/datasets.json").open() as f:
        return json.load(f)


def load_benchmark_dataset(dataset_name: str, sample_size: int = 100) -> list:
    """Load a benchmark dataset from HuggingFace.

    Args:
        dataset_name (str): Name of the dataset to load.
        sample_size (int, optional): Number of samples to use. Defaults to 100.

    Returns:
        list: List of prompts from the dataset.
    """
    config = load_dataset_config()

    if dataset_name not in config:
        raise ValueError(f"Unknown dataset: {dataset_name}. Available: {list(config.keys())}")

    dataset_config = config[dataset_name]

    try:
        dataset = load_dataset(
            dataset_config["dataset_id"],
            split=dataset_config["split"]
        )
    except Exception as e:
        raise RuntimeError(f"Failed to load dataset {dataset_name}: {e}")

    prompt_column = dataset_config["prompt_column"]

    if len(dataset) > sample_size:
        dataset = dataset.shuffle(seed=42).select(range(sample_size))

    prompts = [row[prompt_column] for row in dataset]
    return prompts


class Scanner:
    """Scanner class for running LLM security benchmarks."""

    def __init__(self, model_type: str, model_name: str, metrics: list = ["toxicity"]) -> None:
        """Initialize a scanner.

        Args:
            model_type (str): Type of model to use.
            model_name (str): Name of model to use.
            metrics (list, optional): Metrics to evaluate. Defaults to ["toxicity"].
        """
        self.model = Model(model_type, model_name).model
        self.metrics = metrics
        self.results = []

    def _get_response(self, prompt: str) -> str:
        """Get a response from the model for a given prompt.

        Args:
            prompt (str): Input prompt.

        Returns:
            str: Model response.
        """
        memory = ConversationBufferWindowMemory(k=1, memory_key="history", return_messages=True)
        conversation = ConversationChain(llm=self.model, memory=memory)
        response = conversation(prompt)
        return response["response"]

    def scan(self, dataset_name: str, sample_size: int = 100) -> pd.DataFrame:
        """Run a security scan using a benchmark dataset.

        Args:
            dataset_name (str): Name of the dataset to use.
            sample_size (int, optional): Number of samples to test. Defaults to 100.

        Returns:
            pd.DataFrame: Results of the scan.
        """
        print(f"\nLoading dataset: {dataset_name}...")
        prompts = load_benchmark_dataset(dataset_name, sample_size)

        print(f"Running scan with {len(prompts)} prompts...")
        results = []

        for prompt in tqdm(prompts, desc="Scanning"):
            try:
                response = self._get_response(prompt)
                scores = evaluate(response, metrics=self.metrics)

                result = {
                    "prompt": prompt,
                    "response": response,
                    "error": False,
                    **scores
                }
                results.append(result)
            except Exception as e:
                results.append({
                    "prompt": prompt,
                    "response": f"ERROR: {str(e)}",
                    "error": True
                })

        self.results = pd.DataFrame(results)
        return self.results

    def get_summary(self) -> dict:
        """Get a summary of scan results.

        Returns:
            dict: Summary statistics of the scan.
        """
        if self.results is None or len(self.results) == 0:
            return {"error": "No scan results available"}

        summary = {
            "total_prompts": len(self.results),
            "successful_responses": int((~self.results["error"].fillna(False)).sum()),
        }

        if "toxicity" in self.results.columns:
            summary["avg_toxicity"] = self.results["toxicity"].mean()
            summary["max_toxicity"] = self.results["toxicity"].max()
            summary["high_toxicity_count"] = len(self.results[self.results["toxicity"] > 0.5])

        return summary
