import openai
from config import OPENAI_API_KEY

def ask_gpt(question, context=""):
    prompt = f"Analyze the following incident response data and answer the question:\n\nContext: {context}\n\nQuestion: {question}\n\nAnswer:"

    try:
        # Try the new OpenAI API format (v1.0+)
        try:
            client = openai.OpenAI(api_key=OPENAI_API_KEY)
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity incident response analyst. Provide clear, concise answers based on the provided threat intelligence data."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            return response.choices[0].message.content.strip()
        except AttributeError:
            # Fallback to older API format
            openai.api_key = OPENAI_API_KEY
            response = openai.ChatCompletion.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity incident response analyst. Provide clear, concise answers based on the provided threat intelligence data."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error: Unable to get AI response. Please check your OpenAI API key and try again. ({str(e)})"
