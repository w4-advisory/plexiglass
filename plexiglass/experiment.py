from importlib.resources import files
from .model import Model
from langchain.chains import ConversationChain
from langchain.chains.conversation.memory import ConversationBufferWindowMemory
from langchain.chat_models import ChatLiteLLM
from InquirerPy import inquirer
from .core.evaluate import evaluate
import sys
import json
import pandas as pd
from .utils import colorfy


def _load_templates() -> dict:
    """Load adversarial prompt templates from templates.json.

    Returns:
        dict: Available prompt templates.
    """
    with files("plexiglass").joinpath("config/templates.json").open() as f:
        return json.load(f)

class Experiment:
    def __init__(self, model_type: str, model_name: str, metrics: list = ["toxicity", "pii"]) -> None:
        """Initialize an experiment.

        Args:
            model_type (str): Type of model to use.
            model_name (str): Name of model to use.
            metrics (list, optional): Metrics to evaluate. Defaults to ["toxicity", "pii"].
        """
        self.model = Model(model_type, model_name).model
        self.conversation_history = []
        self.metrics = metrics
        self.templates = _load_templates()

    def _select_template(self) -> str:
        """Select and format an adversarial prompt template.

        Returns:
            str: Formatted prompt with template applied.
        """
        # Select category
        category = inquirer.select(
            message="Select template category:",
            choices=list(self.templates.keys()),
        ).execute()

        # Select specific template
        template_choices = [
            {"name": f"{k}: {v['name']}", "value": k}
            for k, v in self.templates[category].items()
        ]
        template_key = inquirer.select(
            message="Select template:",
            choices=template_choices,
        ).execute()

        template = self.templates[category][template_key]
        prompt_template = template["prompt"]

        # Check if template requires user input
        if "{user_input}" in prompt_template:
            user_input = input(colorfy("[Enter your payload] "))
            formatted_prompt = prompt_template.format(user_input=user_input)
        else:
            formatted_prompt = prompt_template

        print(colorfy("\n[Template Applied] ", "WARNING") + template["name"])
        return formatted_prompt

    def _call_chat(self, llm: ChatLiteLLM, input: str, memory: ConversationBufferWindowMemory = None) -> str:
        """Call the chat function of a model using LiteLLM.

        Args:
            llm (ChatLiteLLM): ChatLiteLLM object in LangChain.
            input (str): Input string.
            memory (ConversationBufferWindowMemory, optional): Windowed buffer memory of LLM in LangChain. Defaults to None.

        Returns:
            str: Response of the model.
        """
        conversation = ConversationChain(
                    llm=llm,
                    memory=memory
        )
        response = conversation(input)
        return response

    def _get_multiline(self, prompt: str = "") -> str:
        """Get multiline input from user using triple quotes.

        Args:
            prompt (str, optional): Initial prompt for input. Defaults to "".

        Returns:
            str: Multiline input joined by newline characters.
        """        
        first = input(prompt)
        
        # Check if input starts with triple quotes
        if first.startswith('"""'):
            lines = [first[3:]]  # Remove the starting triple quotes
            in_multiline = True
            while in_multiline:
                line = input()
                if line.endswith('"""'):
                    lines.append(line[:-3])  # Remove the ending triple quotes
                    in_multiline = False
                else:
                    lines.append(line)
        else:
            # Single line input
            lines = [first]

        return "\n".join(lines)

    def conversation(self) -> None:
        """Start a conversation with a model."""
        memory = ConversationBufferWindowMemory(k=3, memory_key="history", return_messages=True)
        try:
            while True:
                options = inquirer.select(
                    message="Select your input type:",
                    choices=list(["template", "free_text"]),
                ).execute()
                if options == "free_text":
                    user_input = self._get_multiline(prompt = colorfy("[Human Tester] "))
                else:
                    user_input = self._select_template()
                response = self._call_chat(self.model, user_input, memory)
                print(colorfy("\n[LLM] "), response["response"], "\n")
                self.conversation_history.append(response["response"])
        except KeyboardInterrupt:
            print("\nConversation ended.")
            scores = []
            print("\nCalculating results ...")
            for convo in self.conversation_history:
                scores.append(evaluate(convo, metrics=self.metrics))
            results = pd.DataFrame(scores)
            results["response"] = self.conversation_history
            # move column to front
            results = results[["response"]+[col for col in results.columns if col != "response"]]
            print(results)
            sys.exit()