# S.T.I.E.L.D

**S**ecurity **T**hreat **I**ntelligence & **E**arly **L**ayer **D**etection — a T-Pot honeypot deployment enhanced with real-time Telegram and Gmail alerting.

## Overview

This project extends [T-Pot](https://github.com/telekom-security/tpotce) (Deutsche Telekom Security's multi-honeypot platform) with a custom alerting layer that monitors active honeypot containers and sends real-time attack notifications via **Telegram** and **Gmail**.

## Features

- Monitors multiple honeypot services simultaneously via Docker logs
- Sends formatted attack alerts to Telegram and email
- Prevents duplicate/overlapping alerts using file locking
- Tracks event counts per container to avoid re-alerting on the same events
- Includes dedicated parsing for Tanner (web attack) logs

## Honeypots Monitored

| Honeypot | Attack Type |
|---|---|
| Cowrie | Brute Force SSH/Telnet |
| Dionaea | Malware/Exploit Attempts |
| Honeytrap / h0neytr4p | Port Scan/Connection Attacks |
| Mailoney | SMTP Spam/Relay Attempts |
| Heralding | Credential Harvesting |
| CiscoASA | VPN/Cisco Exploits |
| Conpot (IPMI, Kamstrup, IEC104, Guardian AST) | ICS/SCADA Attacks |
| ADBHoney | Android Debug Bridge Exploits |
| RedisHoneypot | Redis Exploits |
| ElasticPot | Elasticsearch Exploits |
| WordPot | WordPress Exploits/Scans |
| Medpot | Medical HL7 Exploits |
| IPPHoney | IPP Printer Exploits |
| SentryPeer | VoIP/SIP Attacks |
| DICOMPot | DICOM Medical Imaging Attacks |
| Miniprint | Printer (PJL) Exploits |
| Tanner | Web Attacks (Path Traversal/LFI, XSS/SQLi, Recon) |

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/alif0602/S.T.I.E.L.D.git
cd S.T.I.E.L.D
```

### 2. Configure credentials

Copy the example file and fill in your own values:

```bash
cp secrets.env.example secrets.env
nano secrets.env
```

```bash
BOT_TOKEN="your_telegram_bot_token"
CHAT_ID="your_telegram_chat_id"
```

Restrict access to the credentials file:

```bash
chmod 600 secrets.env
```

### 3. Configure Gmail alerts

This script uses `msmtp` to send email alerts. Ensure `msmtp` is installed and configured with a Gmail account/app password on your system.

### 4. Run

```bash
chmod +x telegram_alert.sh
./telegram_alert.sh
```

For continuous monitoring, schedule it via cron, e.g. every minute:

```bash
* * * * * /path/to/telegram_alert.sh
```

## Security Notes

- `secrets.env` is excluded from version control via `.gitignore` — never commit real credentials.
- If a token is ever accidentally exposed, revoke and regenerate it immediately via [@BotFather](https://t.me/BotFather).

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE), consistent with the base T-Pot project.

## Acknowledgments

Built on top of [T-Pot](https://github.com/telekom-security/tpotce) by Deutsche Telekom Security GmbH.
