import json
from pathlib import Path
from cyber_range_env import CyberRangeEnvironment

strategies = {
    "Evidence Collector": [
        "request_alice",
        "request_bob",
        "report_vulnerability"
    ],
    "Guessing Agent": [
        "report_vulnerability"
    ],
    "Incomplete Agent": [
        "request_alice",
        "report_vulnerability"
    ]
}

results = []

print("=" * 55)
print("AI RED TEAM CYBER RANGE - AGENT BENCHMARK")
print("=" * 55)

for name, actions in strategies.items():
    env = CyberRangeEnvironment()
    env.reset()

    total_reward = 0
    verified = False

    for action in actions:
        observation, reward, done, info = env.step(action)
        total_reward += reward

        if action == "report_vulnerability":
            verified = observation.get("verified", False)

        if done:
            break

    results.append({
        "agent": name,
        "actions": actions,
        "score": total_reward,
        "verified": verified
    })

    print(f"\nAGENT: {name}")
    print(f"SCORE: {total_reward}/100")
    print(f"VERIFIED: {verified}")

Path("results").mkdir(exist_ok=True)

with open("results/agent_benchmark.json", "w") as file:
    json.dump(results, file, indent=2)

print("\nBenchmark saved: results/agent_benchmark.json")
