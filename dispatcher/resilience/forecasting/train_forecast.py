import argparse
import json
from pathlib import Path

import numpy as np

from dispatcher.resilience.forecasting.forecast import ARTIFACT, HIDDEN, Weights, probability
from dispatcher.resilience.forecasting.forecast_workload import (
    TRAIN_DAYS,
    VALIDATION_DAYS,
    snapshots,
    windows,
)

SEED = 650
EPOCHS = 16
BATCH = 128
RATE = 0.008


def data(days):
    series = [snapshots(day) for day in days]
    examples = [example for day in series for example in windows(day)]
    x = np.asarray([[sample.features() for sample in window] for window, _ in examples])
    y = np.asarray([label for _, label in examples])
    return x, y


def sigmoid(x):
    return 1 / (1 + np.exp(-np.clip(x, -40, 40)))


def forward(x, params):
    inputs, recurrent, biases, output, intercept = params
    h = np.zeros((len(x), HIDDEN))
    c = np.zeros_like(h)
    steps = []
    for xt in x.transpose(1, 0, 2):
        i, f, g, o = np.split(xt @ inputs.T + h @ recurrent.T + biases, 4, axis=1)
        i, f, g, o = sigmoid(i), sigmoid(f), np.tanh(g), sigmoid(o)
        previous_h, previous_c = h, c
        c = f * c + i * g
        h = o * np.tanh(c)
        steps.append((xt, previous_h, previous_c, i, f, g, o, c))
    return h @ output + intercept, h, steps


def gradients(x, y, params):
    _, recurrent, _, output, _ = params
    logits, h, steps = forward(x, params)
    error = (sigmoid(logits) - y) / len(y)
    d_output = h.T @ error
    d_intercept = np.sum(error)
    d_h = error[:, None] * output
    d_c = np.zeros_like(d_h)
    d_inputs, d_recurrent, d_biases = (np.zeros_like(p) for p in params[:3])
    for xt, prev_h, prev_c, i, f, g, o, c in reversed(steps):
        tanh_c = np.tanh(c)
        d_c += d_h * o * (1 - tanh_c**2)
        d_gate = np.concatenate(
            (
                d_c * g * i * (1 - i),
                d_c * prev_c * f * (1 - f),
                d_c * i * (1 - g**2),
                d_h * tanh_c * o * (1 - o),
            ),
            axis=1,
        )
        d_inputs += d_gate.T @ xt
        d_recurrent += d_gate.T @ prev_h
        d_biases += d_gate.sum(axis=0)
        d_h = d_gate @ recurrent
        d_c = d_c * f
    return d_inputs, d_recurrent, d_biases, d_output, d_intercept


def train_numpy(x, y):
    rng = np.random.default_rng(SEED)
    shapes = ((4 * HIDDEN, 3), (4 * HIDDEN, HIDDEN), (4 * HIDDEN,), (HIDDEN,), ())
    bound = HIDDEN**-0.5
    params = [rng.uniform(-bound, bound, size=shape) for shape in shapes]
    first = [np.zeros_like(p) for p in params]
    second = [np.zeros_like(p) for p in params]
    step = 0
    for _ in range(EPOCHS):
        order = rng.permutation(len(x))
        for start in range(0, len(x), BATCH):
            batch = order[start : start + BATCH]
            step += 1
            for i, derivative in enumerate(gradients(x[batch], y[batch], params)):
                first[i] = 0.9 * first[i] + 0.1 * derivative
                second[i] = 0.999 * second[i] + 0.001 * derivative**2
                mean = first[i] / (1 - 0.9**step)
                variance = second[i] / (1 - 0.999**step)
                params[i] -= RATE * mean / (np.sqrt(variance) + 1e-8)
    return params


def train_pytorch(x, y):
    import torch
    from torch import nn

    torch.set_num_threads(1)
    torch.manual_seed(SEED)
    recurrent = nn.LSTM(input_size=3, hidden_size=HIDDEN, batch_first=True)
    head = nn.Linear(HIDDEN, 1)
    optimizer = torch.optim.Adam([*recurrent.parameters(), *head.parameters()], lr=RATE)
    criterion = nn.BCEWithLogitsLoss()
    features, labels = torch.tensor(x, dtype=torch.float32), torch.tensor(y, dtype=torch.float32)
    for _ in range(EPOCHS):
        for indices in torch.randperm(len(x)).split(BATCH):
            optimizer.zero_grad()
            sequence, _ = recurrent(features[indices])
            loss = criterion(head(sequence[:, -1, :]).flatten(), labels[indices])
            loss.backward()
            optimizer.step()
    return [
        recurrent.weight_ih_l0.detach().numpy(),
        recurrent.weight_hh_l0.detach().numpy(),
        (recurrent.bias_ih_l0 + recurrent.bias_hh_l0).detach().numpy(),
        head.weight.detach().numpy()[0],
        head.bias.detach().numpy()[0],
    ]


def calibrated_threshold(probabilities, labels):
    negatives = labels == 0
    positives = ~negatives
    # Выбираем порог по сбалансированной ошибке на валидации.
    candidates = np.arange(0.35, 0.76, 0.05)
    return float(
        min(
            candidates,
            key=lambda cut: (
                (probabilities[negatives] >= cut).mean() + (probabilities[positives] < cut).mean(),
                abs(cut - 0.5),
            ),
        )
    )


def main():
    parser = argparse.ArgumentParser(description="Обучение LSTM для прогнозирования перегрузки.")
    parser.add_argument("--backend", choices=("numpy", "pytorch"), default="numpy")
    parser.add_argument("--output", type=Path, default=ARTIFACT)
    options = parser.parse_args()
    x_train, y_train = data(TRAIN_DAYS)
    x_validation, y_validation = data(VALIDATION_DAYS)
    mean = x_train.mean(axis=(0, 1))
    scale = x_train.std(axis=(0, 1))
    train = train_pytorch if options.backend == "pytorch" else train_numpy
    params = train((x_train - mean) / scale, y_train)
    probabilities = sigmoid(forward((x_validation - mean) / scale, params)[0])
    inputs, recurrent, biases, output, intercept = params
    weights = Weights(
        trained_with=options.backend,
        mean=mean.tolist(),
        scale=scale.tolist(),
        inputs=inputs.tolist(),
        recurrent=recurrent.tolist(),
        biases=biases.tolist(),
        output=output.tolist(),
        intercept=float(intercept),
        threshold=round(calibrated_threshold(probabilities, y_validation), 2),
    )
    for index, (window, _) in enumerate(windows(snapshots(VALIDATION_DAYS[0]))):
        assert abs(probability(weights, window) - probabilities[index]) < 1e-6
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(
        json.dumps(weights.model_dump(), separators=(",", ":")) + "\n", encoding="utf-8"
    )
    print(f"Модель записана в {options.output}. Порог {weights.threshold:.2f}.")


if __name__ == "__main__":
    main()
