# SpiderFoot - AI Assistant Guide

**Last Updated:** 2025-11-16
**Version:** 4.0
**License:** MIT

## Project Overview

SpiderFoot is an open-source OSINT (Open Source Intelligence) automation tool written in Python 3.7+ that has been actively developed since 2012. It integrates with 200+ data sources to collect and analyze intelligence data through a modular, event-driven architecture.

### Key Characteristics
- **Language:** Python 3.7+
- **Architecture:** Modular plugin-based event system with publisher/subscriber model
- **Modules:** 234 OSINT data collection and analysis plugins
- **Correlation Engine:** 37+ YAML-based post-scan analysis rules
- **Interfaces:** Web UI (CherryPy + Mako templates), CLI, JSON API
- **Database:** SQLite with WAL mode for concurrent access
- **Testing:** Pytest with unit, integration, and acceptance tests
- **CI/CD:** GitHub Actions with multi-version (3.7-3.10) and multi-OS testing

### Primary Use Cases
- Offensive security reconnaissance (red team, pentesting)
- Defensive security posture assessment
- OSINT gathering on domains, IPs, emails, persons, Bitcoin addresses, etc.
- Automated threat intelligence correlation

---

## Repository Structure

```
spiderfoot/
├── spiderfoot/              # Core package (5,918 LOC)
│   ├── db.py               # SQLite database layer (1,802 LOC)
│   ├── plugin.py           # Base SpiderFootPlugin class (562 LOC)
│   ├── event.py            # SpiderFootEvent data structure (303 LOC)
│   ├── helpers.py          # Utility functions (1,511 LOC)
│   ├── correlation.py      # YAML correlation engine (1,075 LOC)
│   ├── target.py           # Target representation (223 LOC)
│   ├── threadpool.py       # Thread pool manager (270 LOC)
│   ├── logger.py           # Logging configuration (161 LOC)
│   ├── static/             # Web UI assets (CSS, JS, images)
│   └── templates/          # Mako HTML templates
│
├── modules/                # 234 OSINT modules (sfp_*.py)
│   ├── sfp_dnsresolve.py  # Example: DNS resolution module
│   ├── sfp__stor_db.py    # Storage: Database persistence
│   ├── sfp__stor_stdout.py # Storage: Console output
│   └── sfp_tool_*.py      # External tool integrations (Nmap, Whatweb, etc.)
│
├── correlations/           # 37+ YAML correlation rules
│   ├── template.yaml      # Rule template and reference
│   ├── multiple_malicious.yaml
│   ├── vulnerability_critical.yaml
│   └── cloud_bucket_open.yaml
│
├── test/                   # Test suite
│   ├── unit/              # Unit tests for modules and core
│   ├── integration/       # API integration tests (requires keys)
│   ├── acceptance/        # End-to-end tests
│   └── conftest.py        # Pytest fixtures and configuration
│
├── docs/                   # Sphinx documentation
│
├── sf.py                   # Main entry point (634 LOC)
├── sflib.py               # Core SpiderFoot library (1,664 LOC)
├── sfscan.py              # Scanner orchestrator (586 LOC)
├── sfwebui.py             # Web UI interface (1,884 LOC)
├── sfcli.py               # CLI interface (1,453 LOC)
│
├── requirements.txt       # Python dependencies (27 packages)
├── setup.cfg             # Flake8 linting configuration
├── .pylintrc             # Pylint rules
├── Dockerfile            # Multi-stage Alpine build
├── docker-compose*.yml   # Docker deployment configs
└── README.md             # Main documentation
```

---

## Core Architecture

### Event-Driven Plugin System

SpiderFoot uses a **publisher/subscriber** event model where modules produce and consume events:

```python
# Event Flow Example
Target Input (DOMAIN_NAME: "example.com")
    ↓
sfp_dnsresolve: resolves to IP → produces IP_ADDRESS event
    ↓
sfp_whois: consumes IP_ADDRESS → produces NETBLOCK_OWNER event
    ↓
sfp_bgpview: consumes NETBLOCK_OWNER → produces ASN event
    ↓
Database Storage (sfp__stor_db)
    ↓
Correlation Engine (YAML rules) → generates findings
    ↓
Web UI / CLI / API Export
```

### Module Structure

All modules inherit from `SpiderFootPlugin` in `/spiderfoot/plugin.py`:

```python
class sfp_modulename(SpiderFootPlugin):
    meta = {
        'name': "Module Name",
        'summary': "Brief description",
        'flags': [],  # e.g., ["tool"], ["slow"]
        'useCases': ["Passive", "Investigate", "Footprint"],
        'categories': ["DNS", "Search Engines", "Threat Intelligence"],
        'dataSource': {
            'website': "https://example.com",
            'model': "FREE_NOAUTH_UNLIMITED",  # or TIERED_API, COMMERCIAL_API
            'references': [...],
            'apiKeyInstructions': [...],
            'logo': "url",
            'description': "..."
        }
    }

    opts = {
        'api_key': '',
        'timeout': 30,
        # ... default options
    }

    optdescs = {
        'api_key': 'API key for service',
        'timeout': 'Request timeout in seconds'
    }

    def setup(self, sfc, userOpts=dict()):
        """Initialize module with SpiderFoot context and user options"""
        self.sf = sfc
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        """Return list of event types this module listens for"""
        return ["IP_ADDRESS", "DOMAIN_NAME"]

    def producedEvents(self):
        """Return list of event types this module can produce"""
        return ["NETBLOCK_OWNER", "BGP_AS_OWNER"]

    def handleEvent(self, event):
        """Main event processing logic"""
        eventName = event.eventType
        eventData = event.data

        # Skip if already processed this data
        if eventData in self.results:
            return
        self.results[eventData] = True

        # Process the event
        # ... module-specific logic ...

        # Produce new events
        evt = SpiderFootEvent("NETBLOCK_OWNER", "1.2.3.0/24",
                              self.__name__, event)
        self.notifyListeners(evt)
```

### Event Types (Common)

**Entities** (scan targets):
- `IP_ADDRESS`, `IPV6_ADDRESS`
- `INTERNET_NAME` (hostname/domain)
- `NETBLOCK_OWNER`, `NETBLOCKV6_OWNER`
- `BGP_AS_OWNER` (ASN)
- `EMAILADDR`, `HUMAN_NAME`, `USERNAME`
- `BITCOIN_ADDRESS`, `ETHEREUM_ADDRESS`

**Discovered Data**:
- `AFFILIATE_INTERNET_NAME`, `CO_HOSTED_SITE`
- `LINKED_URL_INTERNAL`, `LINKED_URL_EXTERNAL`
- `SSL_CERTIFICATE_*` (various cert fields)
- `TCP_PORT_OPEN`, `TCP_PORT_OPEN_BANNER`
- `WEBSERVER_BANNER`, `OPERATING_SYSTEM`
- `VULNERABILITY_*` (CVE findings)
- `MALICIOUS_*` (threat intelligence hits)

See `/spiderfoot/db.py` for complete list of entity types.

---

## Development Workflows

### Local Development Setup

```bash
# Clone repository
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot

# Install dependencies
pip3 install -r requirements.txt

# Run in CLI mode (interactive)
python3 sfcli.py

# Run web server (default: http://127.0.0.1:5001)
python3 sf.py -l 127.0.0.1:5001

# Run with custom options
python3 sf.py -l 0.0.0.0:5001 -d  # Debug mode
```

### Docker Development

```bash
# Build and run with docker-compose
docker-compose up

# Development build with live code reload
docker-compose -f docker-compose-dev.yml up

# Full-featured build (includes external tools)
docker-compose -f docker-compose-full.yml up
```

### Testing

**Run Tests:**
```bash
# Install test dependencies
pip install -r test/requirements.txt

# Run all unit tests (excludes integration tests by default)
pytest -n auto --dist loadfile --ignore=test/integration/modules/ \
       --durations=5 --cov-report term --cov=. .

# Run specific test file
pytest test/unit/modules/test_sfp_dnsresolve.py

# Run with verbose output
pytest -v test/unit/

# Integration tests (requires API keys in environment)
pytest test/integration/modules/
```

**CI/CD Pipeline:**
- Automated via GitHub Actions on push to `master` and pull requests
- Matrix testing: Python 3.7, 3.8, 3.9, 3.10 on Ubuntu and macOS
- Linting with flake8 (enforced, build fails on violations)
- Coverage reporting to Codecov
- CodeQL security analysis

---

## Coding Conventions

### Linting Rules (setup.cfg)

```ini
[flake8]
max-line-length = 120
max-complexity = 60
docstring-convention = google
select = C,E,F,W,B,B9,DAR,DUO,R,A,S,Q0,SIM,SFS
extend-ignore = E501 W503 B006 B950 SFS301 SF01 Q000 B902 B907 ANN
```

**Key Points:**
- **Line length:** 120 characters max
- **Docstrings:** Google style required
- **Complexity:** Max cyclomatic complexity of 60
- **Ignored:** Line too long (E501), line break before binary operator (W503)
- **Type hints:** Recommended but not enforced (ANN ignored)

### Coding Style

**1. File Header (all modules):**
```python
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_modulename
# Purpose:      Brief description of module functionality
#
# Author:      Your Name <email@example.com>
#
# Created:     DD/MM/YYYY
# Copyright:   (c) Your Name YYYY
# Licence:     MIT
# -------------------------------------------------------------------------------
```

**2. Import Order:**
```python
# Standard library
import re
import json
from typing import List, Dict, Optional

# Third-party
from bs4 import BeautifulSoup
import requests

# SpiderFoot
from spiderfoot import SpiderFootPlugin, SpiderFootEvent
```

**3. Type Hints (encouraged):**
```python
def resolveTargets(self, target, validateReverse: bool) -> list:
    """Resolve alternative names for a target.

    Args:
        target (SpiderFootTarget): target object
        validateReverse (bool): validate domain names resolve

    Returns:
        list: list of domain names and IP addresses
    """
```

**4. Logging:**
```python
# Available logging methods (inherited from SpiderFootPlugin)
self.debug("Debug message")      # Verbose detail
self.info("Info message")        # General information
self.error("Error message")      # Errors (but continue)
self.fatal("Fatal message")      # Critical errors
```

**5. Error Handling:**
```python
try:
    response = self.sf.fetchUrl(url, timeout=self.opts['timeout'])
    if not response['content']:
        self.error(f"No content from {url}")
        return
except Exception as e:
    self.error(f"Failed to fetch {url}: {e}")
    return
```

**6. Module Conventions:**
- Store processed data in `self.results` dict to avoid duplicates
- Check `self.checkForStop()` in loops to respect user abort
- Use `self.tempStorage()` for temporary data structures
- Always validate input data before processing
- Use `self.sf.*` helper methods (see sflib.py)

### Common SpiderFootLib Methods

```python
# HTTP requests
self.sf.fetchUrl(url, timeout=30, useragent=None, headers=None,
                 postData=None, cookies=None, verify=True)

# DNS resolution
self.sf.resolveHost(hostname)      # Returns list of IPs
self.sf.resolveIP(ip)              # Returns list of hostnames
self.sf.validIP(address)           # Returns bool
self.sf.validIP6(address)          # Returns bool

# Domain/hostname utilities
self.sf.hostDomain(hostname, tldList)  # Extract domain from hostname
self.sf.isDomain(hostname, tldList)    # Check if valid domain

# Data extraction
self.sf.parseEmails(data)          # Extract emails from text
self.sf.parseHashes(data)          # Extract MD5/SHA hashes
self.sf.parseBitcoinAddresses(data)

# IP utilities
self.sf.validIpNetwork(cidr)       # Validate CIDR notation
self.sf.normalizeDNS(data)         # Normalize DNS data
```

---

## Module Development Guide

### Creating a New Module

**Step 1:** Copy template and name appropriately
```bash
cp modules/sfp_template.py modules/sfp_yournewmodule.py
```

**Step 2:** Update module metadata
```python
meta = {
    'name': "Your Module Name",
    'summary': "Clear, concise description of what this module does",
    'flags': [],  # Add ["slow"] if module takes >30s, ["tool"] if external tool
    'useCases': ["Passive", "Investigate", "Footprint"],
    'categories': ["Appropriate Category"],
    'dataSource': {
        'website': "https://datasource.com",
        'model': "FREE_NOAUTH_UNLIMITED",  # See models below
        'references': ["https://docs.url"],
        'apiKeyInstructions': [
            "Step 1: Sign up at https://...",
            "Step 2: Navigate to API settings...",
            "Step 3: Copy API key to SpiderFoot config"
        ],
        'logo': "https://datasource.com/logo.png",
        'description': "Detailed description of data source"
    }
}
```

**Data Source Models:**
- `FREE_NOAUTH_UNLIMITED` - No auth, no limits
- `FREE_NOAUTH_LIMITED` - No auth, rate limited
- `FREE_AUTH_UNLIMITED` - Free API key, no limits
- `FREE_AUTH_LIMITED` - Free API key, rate limited
- `TIERED_API` - Freemium (free tier + paid tiers)
- `COMMERCIAL_API` - Paid only
- `PRIVATE_ONLY` - Requires private instance

**Step 3:** Define options and watched/produced events
```python
opts = {
    'api_key': '',
    'verify': True,
    'timeout': 30,
    'max_pages': 10
}

optdescs = {
    'api_key': 'Your service API key',
    'verify': 'Verify SSL certificates',
    'timeout': 'Timeout for HTTP requests in seconds',
    'max_pages': 'Maximum pages to retrieve'
}

def watchedEvents(self):
    return ["DOMAIN_NAME", "INTERNET_NAME"]

def producedEvents(self):
    return ["AFFILIATE_DOMAIN", "AFFILIATE_INTERNET_NAME", "EMAILADDR"]
```

**Step 4:** Implement handleEvent
```python
def handleEvent(self, event):
    eventName = event.eventType
    srcModuleName = event.module
    eventData = event.data

    # Check if we've already processed this data
    if eventData in self.results:
        self.debug(f"Skipping {eventData}, already processed")
        return
    self.results[eventData] = True

    # Only process certain event types
    if eventName not in self.watchedEvents():
        return

    # Check for scan abort
    if self.checkForStop():
        return

    # Your module logic here
    try:
        data = self.queryApi(eventData)

        for item in data:
            # Create and notify new events
            evt = SpiderFootEvent("EMAILADDR", item, self.__name__, event)
            self.notifyListeners(evt)

    except Exception as e:
        self.error(f"Error processing {eventData}: {e}")
        return
```

**Step 5:** Write tests
```python
# test/unit/modules/test_sfp_yournewmodule.py
import pytest
from modules.sfp_yournewmodule import sfp_yournewmodule
from sflib import SpiderFoot

class TestModuleYourNewModule:
    def test_opts(self):
        module = sfp_yournewmodule()
        assert module.opts is not None

    def test_watchedEvents(self):
        module = sfp_yournewmodule()
        assert "DOMAIN_NAME" in module.watchedEvents()

    def test_producedEvents(self):
        module = sfp_yournewmodule()
        assert "EMAILADDR" in module.producedEvents()
```

---

## Correlation Rules

Correlation rules are YAML files in `/correlations/` that analyze scan results post-collection to identify patterns, anomalies, and risks.

### Rule Structure

```yaml
id: rule_identifier           # Must match filename
version: 1                    # Rule syntax version
meta:
  name: "Human-readable name"
  description: >
    Multi-line description of what this rule detects
    and why it matters for security/OSINT.
  risk: INFO                  # INFO, LOW, MEDIUM, HIGH

collections:
  - collect:
      - method: exact         # exact or regex
        field: type           # type, module, or data
        value: TCP_PORT_OPEN_BANNER
      - method: regex
        field: data
        value: .*[0-9]\.[0-9].*  # Filter for version numbers
      - method: regex
        field: data
        value: not .*HTTP/1.*     # Exclude false positives

aggregation:
  field: data                 # Group results by this field

analysis:
  method: threshold           # threshold, outlier, first_collection_only
  minimum: 2                  # Minimum occurrences

headline: "Software version revealed: {data}"
```

### Common Rule Patterns

**1. Multiple Source Confirmation:**
```yaml
# Detect when multiple threat intel sources flag same IP
collections:
  - collect:
      - method: regex
        field: type
        value: MALICIOUS_.*
aggregation:
  field: entity.data
analysis:
  method: threshold
  field: source.module
  count_unique_only: true
  minimum: 3
headline: "Flagged as malicious by {count} sources: {entity.data}"
```

**2. Outlier Detection:**
```yaml
# Find unusual web servers (shadow IT indicator)
collections:
  - collect:
      - method: exact
        field: type
        value: WEBSERVER_BANNER
aggregation:
  field: data
analysis:
  method: outlier
  maximum_percent: 10
headline: "Uncommon web server detected: {data}"
```

**3. Data Breach Detection:**
```yaml
# Email in multiple breaches
collections:
  - collect:
      - method: exact
        field: type
        value: EMAILADDR_COMPROMISED
aggregation:
  field: entity.data
analysis:
  method: threshold
  minimum: 3
headline: "Email in {count} breaches: {entity.data}"
```

See `/correlations/README.md` and `/correlations/template.yaml` for detailed reference.

---

## Database Schema

SpiderFoot uses SQLite database (`spiderfoot.db`) with following key tables:

### Core Tables

**tbl_scan** - Scan instances
- `scan_id` (TEXT PRIMARY KEY) - UUID
- `scan_name` (TEXT)
- `scan_target` (TEXT) - Target value
- `scan_module_list` (TEXT) - Comma-separated modules
- `scan_type` (TEXT) - Target type
- `scan_status` (TEXT) - STARTED, RUNNING, FINISHED, ABORTED
- `scan_start_time` (INTEGER) - Unix timestamp
- `scan_end_time` (INTEGER)

**tbl_event_types** - Event type registry
- `event` (TEXT PRIMARY KEY) - Event type name
- `event_descr` (TEXT) - Description
- `event_raw` (INTEGER) - 1 if raw data, 0 if processed
- `event_type` (TEXT) - ENTITY, DESCRIPTOR, etc.

**tbl_scan_event** - All events (main data table)
- `scan_instance_id` (TEXT) - FK to tbl_scan
- `generated` (INTEGER) - Unix timestamp
- `event_type` (TEXT) - FK to tbl_event_types
- `event_data` (TEXT) - The actual data
- `event_module` (TEXT) - Source module name
- `source_event_hash` (TEXT) - Parent event hash
- `event_hash` (TEXT PRIMARY KEY) - Unique event identifier
- `event_confidence` (INTEGER) - 0-100
- `event_visibility` (INTEGER) - 0-100
- `event_risk` (INTEGER) - 0-100

**tbl_scan_correlation_results** - Correlation findings
- `scan_instance_id` (TEXT) - FK to tbl_scan
- `correlation_id` (TEXT) - Correlation rule ID
- `result_title` (TEXT) - Headline text
- `result_risk` (TEXT) - INFO/LOW/MEDIUM/HIGH
- `result_hash` (TEXT PRIMARY KEY)

**tbl_config** - Configuration storage
- `scope` (TEXT) - Module name or "GLOBAL"
- `opt` (TEXT) - Option name
- `val` (TEXT) - Option value

### Querying Tips

```python
# Access database in modules via self.__sfdb__
# (Only use this in storage modules or special cases)

# Standard query pattern
conn = self.__sfdb__.dbh
cursor = conn.cursor()
cursor.execute("SELECT * FROM tbl_scan WHERE scan_id = ?", [scanId])
results = cursor.fetchall()
```

For most module development, use `self.notifyListeners()` to create events; the `sfp__stor_db` module handles database writes automatically.

---

## Common Tasks Reference

### Adding Dependencies

**1. Update requirements.txt:**
```bash
echo "newpackage>=1.0.0,<2" >> requirements.txt
```

**2. Update Dockerfile if needed:**
```dockerfile
# In build stage, add any build-time dependencies
RUN apk add --no-cache --virtual build-dependencies \
    gcc \
    new-build-dep
```

**3. Test installation:**
```bash
pip install -r requirements.txt
pytest
```

### Running a Scan Programmatically

```python
from sflib import SpiderFoot
from spiderfoot import SpiderFootDb, SpiderFootTarget, SpiderFootScanner

# Initialize
sfConfig = SpiderFoot({})
sfDb = SpiderFootDb(sfConfig)

# Create scan
scanId = sfDb.scanInstanceCreate("Test Scan", "example.com", "DOMAIN_NAME")

# Configure target
target = SpiderFootTarget("example.com", "DOMAIN_NAME")

# Configure modules
modules = ["sfp_dnsresolve", "sfp_whois", "sfp_shodan"]

# Run scan
scanner = SpiderFootScanner("Test Scan", scanId, target, modules, sfConfig, {})
scanner.startScan()
```

### Exporting Scan Data

**Via CLI:**
```bash
python3 sfcli.py
> export <scanId> json output.json
> export <scanId> csv output.csv
> export <scanId> gexf output.gexf  # Graph format
```

**Via Database:**
```bash
sqlite3 spiderfoot.db "SELECT * FROM tbl_scan_event WHERE scan_instance_id='SCAN-ID'" > output.csv
```

### Git Workflow

```bash
# Create feature branch
git checkout -b feature/new-module

# Make changes and commit
git add modules/sfp_newmodule.py test/unit/modules/test_sfp_newmodule.py
git commit -m "Add new module: sfp_newmodule

- Queries ExampleAPI for domain information
- Produces EMAILADDR and PHONE_NUM events
- Includes unit tests
"

# Push and create PR
git push origin feature/new-module
# Create PR on GitHub targeting master branch
```

**Commit Message Conventions:**
- Clear, descriptive summary line (50 chars)
- Blank line, then detailed description
- Reference issue numbers: `Fixes #123`, `Closes #456`
- Use imperative mood: "Add feature" not "Added feature"

---

## Important File Locations

### Configuration
- `/spiderfoot.db` - SQLite database (created on first run)
- Environment variables:
  - `SPIDERFOOT_DATA` - Data directory path
  - `SPIDERFOOT_LOGS` - Log directory path
  - `SPIDERFOOT_CACHE` - Cache directory path

### Module Directories
- `/modules/` - All OSINT modules
- `/modules/sfp__stor_*.py` - Storage modules (special)
- `/modules/sfp_tool_*.py` - External tool integrations

### Web UI Assets
- `/spiderfoot/static/js/` - JavaScript (jQuery 3.7.1)
- `/spiderfoot/static/css/` - Stylesheets
- `/spiderfoot/templates/` - Mako HTML templates

### Documentation
- `/README.md` - Main project documentation
- `/correlations/README.md` - Correlation rule reference
- `/docs/` - Sphinx documentation source

### Testing
- `/test/unit/modules/` - Module unit tests
- `/test/unit/spiderfoot/` - Core library tests
- `/test/integration/` - API integration tests
- `/test/conftest.py` - Pytest configuration

---

## Tips for AI Assistants

### When Adding New Modules

1. **Always check existing modules first** - Search for similar functionality:
   ```bash
   grep -r "similar_api_name" modules/
   ```

2. **Follow the naming convention** - `sfp_<datasource>.py`

3. **Reuse helper functions** - Check `sflib.py` and `spiderfoot/helpers.py` before writing custom parsers

4. **Test with real data** - Use integration tests with API keys when possible

5. **Document API requirements** - Clear `apiKeyInstructions` in metadata

### When Modifying Core

1. **Check test coverage** - Run tests before and after changes:
   ```bash
   pytest --cov=spiderfoot test/unit/spiderfoot/
   ```

2. **Verify backward compatibility** - Core changes affect all 234 modules

3. **Update type hints** - Core library uses type annotations

4. **Check thread safety** - Database and shared state must be thread-safe

### When Debugging

1. **Enable debug logging:**
   ```bash
   python3 sf.py -l 127.0.0.1:5001 -d
   ```

2. **Check module logs** - Each module logs via `self.debug()`, `self.info()`, `self.error()`

3. **Query database directly:**
   ```bash
   sqlite3 spiderfoot.db
   sqlite> SELECT * FROM tbl_scan_event WHERE event_type='DOMAIN_NAME';
   ```

4. **Use CLI for quick tests:**
   ```python
   python3 sfcli.py
   > start example.com sfp_dnsresolve,sfp_whois
   ```

### When Writing Tests

1. **Mock external API calls** - Don't make real requests in unit tests

2. **Test edge cases:**
   - Empty responses
   - Malformed data
   - API errors (403, 429, 500)
   - Network timeouts

3. **Use fixtures** - Define in `test/conftest.py`:
   ```python
   @pytest.fixture
   def default_options():
       return SpiderFoot({}).optionsForModule('sfp_modulename')
   ```

4. **Integration tests separate** - Place in `/test/integration/` with clear API key requirements

### Common Pitfalls

1. **Duplicate event creation** - Always check `self.results` dict:
   ```python
   if eventData in self.results:
       return
   self.results[eventData] = True
   ```

2. **Infinite event loops** - Don't produce events that trigger the same module

3. **Rate limiting** - Respect API rate limits, use `time.sleep()` when needed

4. **Memory leaks** - Clear temporary storage, don't accumulate unbounded data

5. **Thread safety** - Use locks for shared state, avoid race conditions

6. **SQL injection** - Always use parameterized queries:
   ```python
   cursor.execute("SELECT * FROM table WHERE id = ?", [user_input])
   ```

---

## Recent Development Focus

Based on recent commits:
- **Security updates** - jQuery upgraded to 3.7.1 (CVE mitigations)
- **Module additions** - Google Tag Manager detection
- **Performance** - 60-second timeout for correlations
- **Type safety** - Improved type annotations
- **Code quality** - Fixed comparison operators, updated dependencies

---

## Quick Reference Commands

```bash
# Development
python3 sf.py -l 127.0.0.1:5001 -d        # Web UI with debug
python3 sfcli.py                          # Interactive CLI

# Testing
pytest -n auto --ignore=test/integration/ # Fast parallel tests
pytest -v test/unit/modules/test_sfp_*.py # Specific module test
flake8 modules/sfp_newmodule.py           # Lint check

# Docker
docker-compose up                         # Standard build
docker-compose -f docker-compose-dev.yml up # Dev build

# Database
sqlite3 spiderfoot.db ".schema"           # View schema
sqlite3 spiderfoot.db "SELECT DISTINCT event_type FROM tbl_event_types;" # Event types

# Module Development
cp modules/sfp_template.py modules/sfp_newmodule.py
cp test/unit/modules/test_sfp_template.py test/unit/modules/test_sfp_newmodule.py
```

---

## Additional Resources

- **Official Website:** https://www.spiderfoot.net
- **Documentation:** https://www.spiderfoot.net/documentation
- **GitHub:** https://github.com/smicallef/spiderfoot
- **Discord Community:** https://discord.gg/vyvztrG
- **Twitter:** @spiderfoot

For questions specific to module development, correlation rules, or architecture, refer to:
- `/correlations/README.md` - Correlation rule syntax
- `/correlations/template.yaml` - Annotated rule example
- `/spiderfoot/plugin.py` - Base plugin class with detailed docstrings
- `/README.md` - Full module list and capabilities

---

**End of Guide** - This document should be updated as the project evolves. When making significant architectural changes, update this file accordingly.
