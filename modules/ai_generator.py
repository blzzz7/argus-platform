import os
import json
from openai import OpenAI
import ollama
from sigma.rule import SigmaRule

class AIServiceSwitcher:
    def __init__(self, mode="local", openai_api_key=None):
        """
        1-ci ve 2-ci Is: Cloud (OpenAI) ve Local (Ollama) rejimlari arasinda kecid
        """
        self.mode = mode.lower()
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        
        if self.mode == "cloud":
            if not self.openai_api_key:
                raise ValueError("Cloud rejimi ucun OpenAI API Key daxil edilmelidir!")
            self.client = OpenAI(api_key=self.openai_api_key)

    def generate_sigma_rule(self, entra_json_log: dict) -> str:
        """
        3-cu Is: Entra ID JSON logunu alib Sigma Rule (YAML) formatina cevirir
        """
        prompt = f"""
You are a Cyber Security Threat Detection Engineer.
Convert the following Microsoft Entra ID (Azure AD) JSON log into a valid, standard Sigma Rule in YAML format.

Return ONLY the YAML code without markdown code blocks, explanation, or extra text.

Entra ID JSON Log:
{json.dumps(entra_json_log, indent=2)}
"""

        if self.mode == "cloud":
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert detection engineer generating Sigma rules."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            return response.choices[0].message.content

        elif self.mode == "local":
            response = ollama.chat(
                model="llama3",
                messages=[
                    {"role": "system", "content": "You are an expert detection engineer generating Sigma rules."},
                    {"role": "user", "content": prompt}
                ]
            )
            return response['message']['content']
        else:
            raise ValueError("Kecersiz rejim! Yalniz 'local' ve ya 'cloud' secile biler.")

    def validate_sigma_with_pysigma(self, yaml_content: str):
        """
        3-cu Is: pySigma kitabxanasi ile generasiya olunan qaydani yoxlamaq
        """
        try:
            rule = SigmaRule.from_yaml(yaml_content)
            return True, rule
        except Exception as e:
            return False, str(e)