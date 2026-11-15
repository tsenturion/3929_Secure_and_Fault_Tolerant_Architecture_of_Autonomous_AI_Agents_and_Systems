import json

import httpx2
from pydantic import BaseModel

from dispatcher.models.adapters import OpenAIModel
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.security.filters import SupportExport
from dispatcher.settings import Settings
from dispatcher.workflow.scenarios import SCENARIOS, Action
from dispatcher.workflow.triage import Run

CASE = "REQ-1842"
DEMO_ADDRESS = "buyer-1842@example.invalid"


def support_sample() -> SupportExport:
    return SupportExport(
        description=f"{SCENARIOS[CASE].view.report} Контакт покупателя: {DEMO_ADDRESS}.",
        customer_email=DEMO_ADDRESS,
    )


class ExfiltrationReport(BaseModel):
    run: Run
    requests: list[dict]


class CapturedOpenAI:
    def __init__(self):
        self.requests: list[dict] = []
        self.model = OpenAIModel(
            Settings(_env_file=None, openai_api_key="capture-only", openai_model="demo"),
            post=self.post,
        )

    def post(self, url, *, timeout, trust_env, **options) -> httpx2.Response:
        with httpx2.Client(
            transport=httpx2.MockTransport(self.capture), timeout=timeout, trust_env=trust_env
        ) as client:
            return client.post(url, **options)

    def capture(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        actions = {
            Action(action): label
            for action, label in json.loads(body["input"])["доступные действия"].items()
        }
        result = DemonstrationModel().decide(body["input"], actions)
        return httpx2.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": result.model_dump_json()}],
                    }
                ],
            },
        )
