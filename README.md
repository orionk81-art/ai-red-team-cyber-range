
# AI Red Team Cyber Range

Python Cybersecurity Testing | Vulnerability Detection | Agent Benchmarking

## Project Overview

A local cybersecurity research prototype demonstrating automated security testing, explainable vulnerability classification, scripted agent evaluation, and reproducible benchmarking.

The project includes intentionally vulnerable and protected HTTP applications, security testing scripts, and three generations of rule-based vulnerability classifiers.

## Core Capabilities

- Automated access-control testing
- Vulnerable versus protected application comparison
- Cross-user authorization testing
- RL-style environment with observations, actions, and rewards
- Scripted agent benchmarking
- Explainable vulnerability classification
- Accuracy, precision, and recall measurement
- False-positive and false-negative analysis
- JSON evaluation reports

## Vulnerability Categories

The classifiers analyze descriptions of three vulnerability types:

1. Broken Access Control
2. SQL Injection
3. Insecure Configuration

These classifiers analyze text. They are not live vulnerability scanners or trained AI models.

## Classifier Benchmark Results

| Evaluation | Accuracy |
|---|---|
| Version 1 baseline | 50% (6/12) |
| Version 2 development | 100% (12/12) |
| Version 2 fresh evaluation | 25% (3/12) |
| Version 3 diagnostic | 100% (12/12) |

Version 3 combines security indicators and provides explanations for its predictions.

**Important:** Version 3 was developed after examining the fresh evaluation scenarios. Its diagnostic accuracy is not an independent estimate of performance on unseen data.

## Agent Benchmark Results

| Scripted Agent | Score | Verified |
|---|---|---|
| Evidence Collector | 100/100 | Yes |
| Guessing Agent | 0/100 | No |
| Incomplete Agent | 0/100 | No |

The agents are scripted strategies, not trained reinforcement-learning agents.

## Requirements

- Python 3.10 or newer
- Standard-library Python scripts require no external dependencies

## Running the Lab

Open three PowerShell terminals in the project directory.

Terminal 1:

```powershell
python vulnerable_app.py
```

Terminal 2:

```powershell
python secure_app.py
```

Terminal 3:

```powershell
python security_comparison.py
python agent_benchmark.py
```

The vulnerable application runs on `127.0.0.1:8000`.

The protected application runs on `127.0.0.1:8001`.

## Running the Classifiers

Version 2:

```powershell
python improved_classifier.py
```

Version 3:

```powershell
python classifier_v3.py
```

Version 3 diagnostic benchmark:

```powershell
python benchmark_v3.py
```

Version 2 development benchmark:

```powershell
python held_out_benchmark.py
```

Benchmark reports are saved in the `results/` directory.

## Security Scope

This project is an intentionally vulnerable, localhost-only educational lab.

All records are fictional.

The protected application uses a client-supplied identity header to simulate authorization. It does not provide production-grade authentication.

Testing is restricted to the local lab environment.

## Current Limitations

- Rule-based classifiers, not trained AI models
- Small, manually authored evaluation datasets
- Version 3 lacks independent validation
- Scripted agents rather than learned policies
- No complete Gymnasium integration
- No production-grade authentication

## Planned Improvements

- Independent evaluation on untouched scenarios
- Randomized security challenges
- Stronger reward verification
- Additional vulnerability categories
- Improved false-positive testing
- Gymnasium-compatible environment
- Evaluation of trained or external AI agents

## Skills Demonstrated

Python automation, cybersecurity testing, access-control analysis, vulnerability classification, benchmark design, evaluation metrics, JSON reporting, and technical documentation.
