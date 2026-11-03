from detoxify import Detoxify
from transformers import AutoTokenizer, AutoModelForTokenClassification
from transformers import pipeline
import pandas as pd

def evaluate_toxcity(prompt: str) -> dict:
    """Evaluate toxicity of a prompt.

    Args:
        prompt (str): String to evaluate.

    Returns:
        dict: toxicity score.
    """
    return Detoxify('original').predict(prompt)

def evaluate_pii(prompt: str) -> list:
    """Evaluate PII of a prompt.

    Args:
        prompt (str): String to evaluate.

    Returns:
        list: List of PII detected.
    """
    
    tokenizer = AutoTokenizer.from_pretrained("dslim/bert-base-NER")
    model = AutoModelForTokenClassification.from_pretrained("dslim/bert-base-NER")

    nlp = pipeline("ner", model=model, tokenizer=tokenizer)
    ner_results = nlp(prompt)
    return ner_results


def evaluate(prompt: str, metrics: list = ["toxicity", "pii"]) -> dict:
    """Evaluate a prompt given a list of metrics.

    Args:
        prompt (str): String to evaluate.
        metrics (list, optional): Metrics to evaluate. Defaults to ["toxicity", "pii"].

    Returns:
        dict: Dictionary containing results of evaluation.
    """
    unknown = set(metrics) - {"toxicity", "pii", "pii_detection"}
    if unknown:
        raise ValueError(f"Unsupported metrics: {sorted(unknown)}")
    results = {}
    for metric in metrics:
        if metric == "toxicity":
            toxicity = evaluate_toxcity(prompt)
            results.update(toxicity)
        elif metric in {"pii", "pii_detection"}:
            pii = evaluate_pii(prompt)
            results.update({"pii_detected": pii})
    return results

if __name__ == "__main__":
    evaluate()