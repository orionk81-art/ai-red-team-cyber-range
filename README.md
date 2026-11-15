
# AI Red Team Cyber Range

### Python Cybersecurity Automation | Access-Control Testing | Agent Evaluation

A reproducible, localhost-only cybersecurity lab that demonstrates broken access control, compares vulnerable and protected application behavior, evaluates scripted security-testing agents, and explores rule-based vulnerability classification.

Built as a cybersecurity portfolio project using Python and standard-library tools.

## Project Highlights

- Automated one-command cybersecurity demonstration
- Intentionally vulnerable and protected HTTP applications
- Six automated access-control security tests
- Three scripted agent evaluation strategies
- Rule-based vulnerability classification experiments
- JSON benchmark reporting
- Documented security limitations and validation results

## Quick Start

**Requirements:** Python 3.10 or newer.

Clone the repository:

```powershell
git clone https://github.com/orionk81-art/ai-red-team-cyber-range.git
cd ai-red-team-cyber-range
```

Run the demonstration:

```powershell
python run_demo.py
```

The launcher automatically:

1. Starts the vulnerable application on `127.0.0.1:8000`.
2. Starts the protected application on `127.0.0.1:8001`.
3. Runs the security comparison.
4. Executes the scripted agent benchmark.
5. Saves JSON results.
6. Shuts down both applications.

Ports 8000 and 8001 must be available before launching.

## Architecture

```text
AI Red Team Cyber Range
|
|-- run_demo.py
|     Automated demonstration launcher
|
|-- vulnerable_app.py
|     Intentionally vulnerable HTTP application
|
|-- secure_app.py
|     Simulated access-control protection
|
|-- security_comparison.py
|     Six HTTP security tests
|
|-- cyber_range_env.py
|     Custom agent-testing environment
|
|-- agent_benchmark.py
|     Scripted agent evaluation
|
|-- classifier_v3.py ... classifier_v7.py
|     Experimental rule-based classifiers
|
|-- results/
|     JSON benchmark reports
|
|-- README.md
```

## Security Comparison

The lab compares access-control behavior between two local HTTP applications.

| Test | Expected HTTP Status | Observed Result |
|---|---:|---|
| Vulnerable: anonymous reads Alice | 200 | Pass |
| Vulnerable: anonymous reads Bob | 200 | Pass |
| Protected: anonymous blocked | 401 | Pass |
| Protected: Alice reads Alice | 200 | Pass |
| Protected: Alice denied Bob | 403 | Pass |
| Protected: Bob reads Bob | 200 | Pass |

**Observed result: 6/6 tests passed.**

The intentionally vulnerable application allows access to fictional records without appropriate authorization.

The protected application demonstrates authentication and authorization decisions using a simulated user identity.

**Important:** The protected application trusts a client-supplied `X-Lab-User` header. This is suitable for illustrating authorization logic but does not provide secure authentication.

Results are written to `results/security_comparison.json`.

## Scripted Agent Benchmark

The project evaluates three scripted strategies in a controlled environment.

| Agent | Observed Score | Verified |
|---|---:|---|
| Evidence Collector | 100/100 | Yes |
| Guessing Agent | 0/100 | No |
| Incomplete Agent | 0/100 | No |

Results are saved to `results/agent_benchmark.json`.

These agents are scripted strategies, not trained reinforcement-learning models. Their scores measure performance under this lab's evaluation rules, not general-purpose AI capability.

## Vulnerability Classification Experiments

The project includes experimental Python classifiers that use manually authored detection rules.

These classifiers are not trained machine-learning models.

### Evaluation History

| Version | Evaluation | Result |
|---|---|---|
| V5 | Development scenarios | 24/24 (100%) |
| V5 | First-run fresh validation | 25/40 (62.5%) |
| V6 | Development scenarios | 40/40 (100%) |
| V6 | First-run independent challenge | 12/60 (20%) |
| V7 | Revised challenge scenarios | 45/60 (75%) |

The V7 evaluation reused previously examined scenarios and therefore is not independent validation.

The differences between development and independent evaluation results demonstrate the limitations of hand-authored rules and the risk of overfitting.

The reported scores should not be interpreted as real-world vulnerability detection accuracy.

## Running Individual Components

Start the vulnerable application:

```powershell
python vulnerable_app.py
```

Start the protected application in a separate terminal:

```powershell
python secure_app.py
```

Run the security comparison in another terminal:

```powershell
python security_comparison.py
```

Run the agent benchmark:

```powershell
python agent_benchmark.py
```

For the complete demonstration, use `python run_demo.py` instead.

## Security Scope and Limitations

- Localhost-only educational simulation
- Fictional records and synthetic test scenarios
- No production-grade authentication
- Client-controlled identity header in the protected application
- Scripted agents rather than learned policies
- Rule-based classifiers rather than trained AI
- Small, manually authored evaluation datasets
- No untouched independent validation for V7
- No complete Gymnasium integration
- No claim of production-ready security or real-world detection accuracy

Only test systems and environments you own or are authorized to assess.

## Skills Demonstrated

Python automation, HTTP security testing, broken access-control analysis, security test design, agent evaluation, vulnerability classification, benchmark methodology, JSON reporting, reproducible demonstrations, and technical documentation.

## Future Improvements

- Real authentication and session management
- Stronger authorization testing
- Independent validation using untouched scenarios
- Improved false-positive and false-negative analysis
- Gymnasium-compatible environment
- Evaluation of trained or externally provided AI agents

## License

No license is currently specified. All rights are reserved unless a license is added.
