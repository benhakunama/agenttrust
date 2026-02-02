# 🛡️ AgentTrust

**Runtime security, observability, and compliance for AI agents.**

AgentTrust provides a comprehensive security layer for autonomous AI agents, offering real-time monitoring, threat detection, compliance enforcement, and cryptographic identity management.

## Quick Start (3 lines)

```python
import agenttrust

at = agenttrust.init(framework="langchain")
# That's it — monitoring is now active
```

## Installation

```bash
pip install agenttrust
```

With LangChain integration:
```bash
pip install agenttrust[langchain]
```

## CLI

```bash
# Initialize for your framework
agenttrust init --framework langchain

# Real-time monitoring dashboard
agenttrust monitor --live

# Check agent fleet status
agenttrust status

# View configuration
agenttrust config
```

## Four Security Layers

### Layer 1: AgentObserve
Traces every agent action with <5ms overhead. Tool calls, LLM invocations, chain executions — all captured.

### Layer 2: AgentProtect
Behavioral firewall with pattern-based threat detection: prompt injection, privilege escalation, data exfiltration, and behavioral drift.

### Layer 3: AgentComply
Compliance engine supporting EU AI Act, NIST RMF, ISO 42001, and SOC2. Automated audit trails and risk dashboards.

### Layer 4: AgentIdentity
Cryptographic identity management for agents. Register, verify, and compute trust scores across your agent fleet.

## License

MIT
