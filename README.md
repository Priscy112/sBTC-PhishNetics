

# sBTC-PhishNetic - Anti-Phishing Smart Contract

A secure and decentralized smart contract built using Clarity for combating phishing attacks by allowing trusted entities to register websites, report phishing threats, and verify reports. The system uses economic incentives and trust scoring to ensure reliable threat detection and website protection.

---

## 📜 Overview

The **Anti-Phishing Smart Contract** provides a trustless framework where:

* Website owners can register secure websites by locking collateral.
* Security monitors with reputation can submit and verify phishing reports.
* Threat evidence and SSL certificates are validated on-chain.
* A global security level governs system parameters.
* Admins can manage system-level configurations and perform emergency actions.

---

## 🔐 Core Features

### ✅ Website Registration

* Only the contract owner can register secure websites.
* A collateral of STX is locked during registration.
* SSL certificates and website identifiers are validated.

### 🕵️‍♂️ Threat Reporting

* Security monitors can submit phishing reports with evidence.
* Reports have a cooldown period of 24 hours.
* Evidence must meet length and character restrictions.

### 🔍 Threat Verification

* Monitors can verify existing phishing reports.
* Verifications affect the website’s phishing risk score.
* False verification penalizes monitors.

### 🧑‍💻 Security Monitors

* Must stake collateral to participate.
* Reputation and trust score are tracked on-chain.
* Earn trust through verified reports.

### ⚙️ Administration

* Contract owner can update global settings.
* Emergency pause/unpause functionality available.
* Ownership transfer with safeguard against null addresses.

---

## 🧪 Validation Rules

### Website Identifier

* Length between 3 to 255 characters.
* Disallows `.`, `/`, and spaces.

### SSL Certificate

* Between 5 to 50 characters.
* Disallows `<` and `>`.

### Threat Evidence

* Between 10 to 500 characters.
* Disallows `<` and `>`.

### Threat Severity

* Must be between 1 and 100.

### Security Level

* Must be between 1 and 10.

---

## 📊 Data Structures

### `registered_secure_websites`

Stores metadata for secure websites (owner, SSL cert, risk score, audit dates).

### `phishing_incident_reports`

Stores phishing reports submitted by monitors.

### `monitor_site_performance`

Tracks monitor activity, including reputation and verified reports.

### `website_audit_history`

Stores audit records per website.

### `security_monitor_status`

Tracks staked collateral, reputation, and monitor activity.

---

## ⚠️ Error Codes

| Code   | Description                |
| ------ | -------------------------- |
| `u100` | Unauthorized access        |
| `u101` | Website already registered |
| `u102` | Website not found          |
| `u103` | Contract is paused         |
| `u104` | Insufficient collateral    |
| `u105` | Cooldown period active     |
| `u106` | Exceeds system limits      |
| `u107` | Timing violation           |
| `u400` | Malformed website ID       |
| `u401` | Invalid certificate        |
| `u402` | Insufficient evidence      |
| `u403` | Invalid threat level       |
| `u404` | Invalid security level     |
| `u405` | Invalid admin address      |

---

## 🛠️ Key Constants

* `COOLDOWN_PERIOD_SECONDS`: `86400` (24 hours)
* `REQUIRED_COLLATERAL_AMOUNT`: `1,000,000` microSTX
* `REQUIRED_MONITOR_REPUTATION`: `50`
* `MAX_EVIDENCE_STRING_LENGTH`: `500`

---

## 🧩 Public Functions

| Function                      | Description                              |
| ----------------------------- | ---------------------------------------- |
| `register-secure-website`     | Registers a new website                  |
| `submit-phishing-report`      | Submit a phishing report                 |
| `verify-phishing-report`      | Verify the validity of a report          |
| `register-security-monitor`   | Stake collateral to become a monitor     |
| `update-security-level`       | Change the global protection level       |
| `set-emergency-pause`         | Pause or unpause the contract            |
| `transfer-contract-ownership` | Transfer ownership                       |
| `initialize-contract`         | Initialize settings for first-time setup |

---

## 🔍 Read-Only Functions

* `get-website-security-info`
* `has-reported-threats`
* `get-monitor-reputation`

---

## 🚧 Limitations

* Only contract owner can register websites.
* Reputation and trust scoring mechanisms are basic.
* External SSL validation is not truly verifiable on-chain.

---

## 🪙 Token Flow (STX)

* Website registration requires STX collateral.
* Monitors must stake STX to participate.
* All STX transfers are handled within the contract securely.

---
