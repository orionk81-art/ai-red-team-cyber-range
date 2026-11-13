# AI Red Team Cyber Range

A local cybersecurity evaluation prototype demonstrating automated
access-control testing, scripted agent evaluation, and RL-style scoring.

## Project capabilities

- Intentionally vulnerable HTTP application
- Protected comparison application
- Automated unauthenticated access testing
- Cross-user authorization testing
- Negative-control validation
- RL-style reset, step, observation, and reward interface
- Scripted agent strategy benchmarking
- JSON evaluation reports

## Requirements

- Python 3.10 or newer
- No third-party Python dependencies required

## Running the lab

Open separate terminals in the project directory.

Terminal 1:

    python vulnerable_app.py

Terminal 2:

    python secure_app.py

Terminal 3:

    python security_comparison.py
    python negative_control.py
    python cross_user_access.py
    python agent_benchmark.py
    python multi_target_agent.py

The vulnerable application listens on 127.0.0.1:8000.
The protected application listens on 127.0.0.1:8001.

## Security scope

This is an intentionally vulnerable, localhost-only educational lab.
All records are fictional.

The protected application uses a client-supplied identity header
for simulation. This is not production-grade authentication.

## Current limitations

- Scripted agents, not trained AI models
- Fixed scenarios and deterministic tests
- No randomized or held-out benchmark suite
- No real authentication system
- No complete Gymnasium integration

## Planned improvements

- Randomized challenge generation
- Stronger reward verification
- Multiple vulnerability classes
- Reproducible benchmark runs
- Agent evaluation across unseen scenarios
