# Simple Protocol Management Workflow

## Core Requirements ✅

1. **Add protocol first** (with ports from file)
2. **Link validator addresses to protocol** (simple foreign key)  
3. **Ensure recon agents link to the right protocol**

## Simple Workflow

### 1. Add a New Protocol

Create a protocol JSON file (see `examples/example_protocol.json`):

```json
{
    "name": "myprotocol", 
    "display_name": "My Protocol",
    "category": "blockchain",
    "ports": [8080, 9090],
    "endpoints": ["/health"],
    "banners": ["myprotocol-node"],
    "rpc_methods": ["myprotocol_getInfo"],
    "metrics_keywords": ["myprotocol_metrics"], 
    "http_paths": ["/metrics"],
    "identification_hints": ["myprotocol blockchain"]
}
```

Add the protocol:
```bash
python tools/simple_protocol_manager.py --add-protocol myprotocol.json
```

This automatically generates the signature too.

### 2. Check What Protocols Exist

```bash
python tools/simple_protocol_manager.py --list
```

Shows all protocols with validator counts and signature status.

### 3. Run Reconnaissance  

The recon agents automatically:
- Check if their protocol exists
- Verify it has a signature  
- Get the protocol_id for linking validators

```bash
python -m agents.recon.sui_agent
python -m agents.recon.filecoin_agent  
```

### 4. Manually Link Validators (if needed)

```bash
python tools/simple_protocol_manager.py --link-validator validator.example.com myprotocol
```

## That's It! 

The important things are covered:
- ✅ **Ports and signature exist** (protocol file + auto-signature)
- ✅ **Recon links to right protocol** (automatic protocol_id lookup)
- ✅ **Simple workflow** (add protocol → run recon)

## Current Database Migration

The migration we already did handles the database structure:
- ✅ `validator_addresses.protocol_id` foreign key exists
- ✅ Old data migrated (379 addresses)
- ✅ Foreign key constraints enforced

So now it's just about **adding new protocols** and **running recon agents**.
