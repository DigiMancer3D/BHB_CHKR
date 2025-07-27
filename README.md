# BTC Checker [/BHB_CHKR/BTC_Checker.py]

![BTC Checker Icon](BTC_Checker.png)

BTC Checker is a lightweight desktop application built in Python that allows users to quickly verify the status of Bitcoin Unspent Transaction Outputs (UTXOs) and Transactions (TXs). It uses efficient Bloom filters for local, probabilistic checks to determine if a UTXO has been spent or if a TX has been seen on the blockchain. For precise verification, it integrates with public Bitcoin APIs (like mempool.space and blockstream.info) or a local Bitcoin node via RPC. The app supports both online and offline modes, with background syncing capabilities for keeping the local data up-to-date.

## Key Use Cases

- Checking if a UTXO (e.g., `txid:vout`) is still valid (unspent) or has been spent.
- Verifying if a TXID exists on the blockchain or in the mempool.
- Offline probabilistic checks using pre-synced data snapshots.
- Background operation for continuous blockchain monitoring without the GUI.

The app is designed for Bitcoin enthusiasts, developers, or users who need a simple tool for transaction validation without running a full node (though local node support is available for enhanced privacy and accuracy).

## Features

- **Probabilistic Local Checks**: Uses Bloom filters to store spent UTXOs and seen TXIDs, allowing fast lookups with low memory usage (~256KB per filter).
- **Online Verification**: Queries public APIs for detailed metadata (e.g., value, address, fee, block height) and confirms status.
- **Offline Mode**: Falls back to Bloom filter checks when no internet is available, providing "likely" status based on synced data.
- **Blockchain Syncing**:
  - Forward polling: Checks for new blocks every ~4 minutes.
  - Backward historical sync: Processes older blocks in batches to build the filter dataset.
- **Local Node Support**: Connect to a personal Bitcoin Core node via RPC for private queries (avoids public APIs).
- **GUI Interface**: Built with Tkinter for easy input and output display, including clickable links to explorers.
- **State Persistence**: Saves Bloom filters and sync progress to a JSON file for resuming across sessions.
- **Background Mode**: Run syncing in the background without the GUI, with options to re-open or exit.
- **Rate Limiting**: Built-in delays to respect API limits and avoid bans.

## How It Works

### Core Components

- **Bloom Filters**:
  - Two filters are maintained:
    - `bloom_utxo`: Tracks spent UTXOs as keys (TXID bytes + vout as 4-byte integer).
    - `bloom_tx`: Tracks seen TXIDs.
  - Size: 2,097,152 bits (~256KB) with 3 hash functions for low false positives.
  - Items are added during blockchain syncing; checks are probabilistic (false positives possible, but no false negatives).
- **Syncing Mechanism**:
  - **Forward Polling**: A thread polls the current blockchain height every 238 seconds (~4 minutes). For each new block, it fetches TX details and adds spent inputs to `bloom_utxo` and TXIDs to `bloom_tx`.
  - **Backward Historical Sync**: Another thread processes blocks backward from the current height (up to a limit of 144 blocks initially, in batches of 10) to populate filters with historical data.
  - **Data Sources**:
    - Public APIs (mempool.space for recent, blockstream.info for historical).
    - Or local Bitcoin node RPC if configured (methods like `getblockhash`, `getblock`).
- **Checking Logic**:
  - Input: TXID (64 hex chars) or UTXO (`txid:vout`, where vout is an integer).
  - Bloom Check: Quick local lookup for "likely spent/seen" or "definitely not".
  - Online Confirmation: If connected, queries API for exact status (e.g., spent/unspent, confirmed/in mempool) and metadata.
  - Offline: Relies solely on Bloom filters with a note for potential offline confirmation needs.
  - Updates filters based on API results for future accuracy.
- **State Management**:
  - Saved to `bloom_state.json`: Includes encoded Bloom filters, hashes for integrity, current/backward heights, synced blocks, and node config.
  - Loaded on startup; integrity checked via SHA256 hashes.
- **Networking**:
  - Rate-limited requests (1s delay + retries on 429 errors).
  - Fallback to offline mode if no internet (checks via a Google ping).

### Technical Flow

1. On launch: Load state or initialize filters and heights.
2. Start sync threads (forward and backward).
3. User inputs TXID or UTXO in GUI and clicks "Check".
4. Parse input, perform Bloom check.
5. If online, fetch API data; update status and filters.
6. Display results with metadata and explorer link.
7. On close: Option to background sync or exit silently, saving state.

## Potential Limitations

- Bloom filters have false positives (e.g., "likely spent" might be wrong, but "definitely not" is accurate).
- Historical sync is limited to recent blocks (configurable via `BACKWARD_LIMIT`); full history would require more time/memory.
- Public APIs may have downtime or rate limits; local node recommended for heavy use.
- No support for testnet or other chains.

## Requirements

- **Python 3.12+** (tested with 3.12.3, but compatible with 3.x).
- **Standard libraries**: `hashlib`, `struct`, `time`, `threading`, `json`, `base64`, `sys`, `os`.
- **External libraries** (install via pip if missing):
  - `requests` for API calls.
  - `tkinter` (usually bundled with Python; install `python3-tk` on Linux if needed).
  - `webbrowser` (standard).
- **Optional**: A local Bitcoin Core node (v0.21+ recommended) for RPC access.
- **Icon files**: `BTC_Checker.png` and `BTC_Checker.ico` (for GUI icon; optional, but place in the same directory).

No additional package installations are needed beyond `requests` if not present.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/btc-checker.git
   cd btc-checker
   ```
2. Install dependencies (if needed):
   ```bash
   pip install requests
   ```
3. (Optional) Place icon files (`BTC_Checker.png` for non-Windows, `BTC_Checker.ico` for Windows) in the root directory.
4. Run the app:
   ```bash
   python btc_checker.py
   ```

## Usage

### Running the App

- Launch: `python btc_checker.py`.
- The GUI will open showing a text entry for input and buttons.

### Checking a UTXO or TX

1. Paste a valid input into the entry field:
   - UTXO: `txid:vout` (e.g., `a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0`).
   - TXID: `txid` (e.g., `a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d`).
2. Click **Check**.
3. Results appear in the output area:
   - Status (e.g., "VALID", "SPENT (block: 123456)", "Likely SPENT").
   - Bloom check result.
   - Metadata (e.g., Value, Address, Fee, Inputs/Outputs).
   - Clickable link to mempool.space explorer.
4. If offline, a note will indicate reliance on local snapshots.

### Adding a Local Node

1. Click **Add Node**.
2. Enter details in the dialog:
   - Host: e.g., `localhost`.
   - Port: e.g., `8332`.
   - User/Pass: RPC credentials from your `bitcoin.conf`.
3. Click **Save**. The app will now prefer RPC over public APIs.

### Sync Progress

- Shown at the bottom: "Synced Blocks / Current Height" (e.g., "100 / 800000").
- Sync happens automatically in threads.

### Closing the App

- On window close: Prompt to "Sync or go Silent?"
  - **Yes**: Hide GUI, continue syncing in background (console input to re-open or exit).
  - **No**: Stop syncing and exit.

### Background Mode

- While in background: Press **Enter** to re-open GUI or type `exit` to quit.
- State is saved periodically.

## Configuration

- Edit constants in code if needed (e.g., `POLL_INTERVAL`, `BACKWARD_LIMIT`, `BATCH_SIZE`).
- State file: `bloom_state.json` (delete to reset sync).

## Credits

Designed by **@Z0M8I3D 3Douglas "3D"** & Code Formed by **@Grok xAI xTwitter [2025]**
