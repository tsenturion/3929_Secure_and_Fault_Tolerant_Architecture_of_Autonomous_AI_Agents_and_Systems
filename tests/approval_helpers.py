def issue_approval(client, path, *, headers=None):
    draft = client.get(path, headers=headers)
    draft.raise_for_status()
    current = draft.json()
    return client.post(
        f"{path}/approval-token",
        json={"scenario_id": current["scenario_id"], "recommendation": current["recommendation"]},
        headers=headers,
    )


def commit_approval(client, path, grant, *, headers=None):
    return client.post(
        f"{path}/resolution",
        json={"decision": "approve", "transaction_token": grant["token"]},
        headers={**(headers or {}), "Idempotency-Key": grant["idempotency_key"]},
    )


def approve(client, path, *, headers=None):
    issued = issue_approval(client, path, headers=headers)
    if not issued.is_success:
        return issued
    return commit_approval(client, path, issued.json(), headers=headers)
