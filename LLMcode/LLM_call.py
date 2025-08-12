import requests
import os
import json
from LLMcode.constants import (
    PROMPT_TOKEN_LIMIT,
    DEFAULT_TIMEOUT_SECONDS
)

def LLM_call(prompt: str = "", system_prompt: str = "", max_tokens: int = PROMPT_TOKEN_LIMIT) -> tuple[int, str]:
        api_endpoint = f"https://api.deepseek.com/chat/completions"
        api_key = os.environ.get('LLM_API_KEY', '')
            
        if not api_key:
            return False, "LLM_API_KEY environment variable is not set", {}
        
        # Prepare headers and payload
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        
        payload = json.dumps({
            "messages": [
                {
                "content": system_prompt,
                "role": "system"
                },
                {
                "content": prompt,
                "role": "user"
                }
            ],
            "model": "deepseek-chat",
            "frequency_penalty": 0,
            "max_tokens": max_tokens,
            "presence_penalty": 0,
            "response_format": {
                "type": "text"
            },
            "stop": None,
            "stream": False,
            "stream_options": None,
            "temperature": 1,
            "top_p": 1,
            "tools": None,
            "tool_choice": "none",
            "logprobs": False,
            "top_logprobs": None
            })
           
        response = requests.post(
            api_endpoint,
            headers=headers,
            data=payload,
            timeout=DEFAULT_TIMEOUT_SECONDS
        )
        response_data = response.json()
        if not response_data.get('choices'):
            raise ValueError(f"API response missing 'choices' or it's empty, current response: {response.text}")
        response_text = response_data['choices'][0].get('message', {}).get('content', '')
        return response.status_code, response_text