from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI()

for model in sorted(client.models.list().data, key=lambda m: m.id):
    print(model.id)