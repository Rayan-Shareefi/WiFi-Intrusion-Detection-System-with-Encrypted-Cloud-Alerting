# Documentation

The project overview is in the [root README](../README.md). These are the detailed guides:

| Guide | What it covers |
|---|---|
| [SETUP.md](SETUP.md) | The full build, milestone by milestone (M0 to M9) |
| [COST-SAFETY.md](COST-SAFETY.md) | Keeping the project at $0: free-tier limits, budgets, billing alarms |
| [ZERO-COST-FOREVER.md](ZERO-COST-FOREVER.md) | Running for years at $0 with the HTTPS Function-URL path (no IoT Core) |
| [HARDENING.md](HARDENING.md) | The security-review fixes and the sensor-offline alarm |
| [DASHBOARD-APP.md](DASHBOARD-APP.md) | Deploying the desktop and iPhone dashboard app |
| [SECURITY-REVIEW.md](SECURITY-REVIEW.md) | Threat model, findings with severities, hardening roadmap |

AWS console walkthroughs are next to the code they configure:
- [../cloud/aws-iot-setup.md](../cloud/aws-iot-setup.md): Thing, X.509 certificate, IoT policy, endpoint
- [../cloud/cloud-alerting-setup.md](../cloud/cloud-alerting-setup.md): SNS topic, Lambda, IoT Rule

Screenshots and the demo animation are in [media/](media).
