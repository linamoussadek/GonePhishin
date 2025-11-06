# Gone Phishin' - Chrome Extension

A Chrome extension for phishing protection and TLS certificate verification using notary services.

## Features

- **TLS Certificate Verification**: Verifies SSL/TLS certificates using notary services
- **MITM Detection**: Detects potential man-in-the-middle attacks by comparing certificates
- **HTTPS Enforcement**: Forces HTTPS connections and blocks mixed content
- **Real-time Monitoring**: Monitors all HTTPS connections in real-time
- **Heuristic Analysis**: Analyzes page content for phishing indicators

## Prerequisites

- **Node.js** (v14 or higher) - [Download](https://nodejs.org/)
- **Chrome Browser** (for extension)
- **ngrok** (included in `ngrok/` folder, or download from [ngrok.com](https://ngrok.com/))
- **Git** (for version control)
- **PowerShell** (Windows - comes pre-installed)

## Setup

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd GonePhishin
```

### 2. Setup ngrok Authentication

1. Sign up for a free ngrok account at [https://dashboard.ngrok.com/signup](https://dashboard.ngrok.com/signup)
2. Get your authtoken from [https://dashboard.ngrok.com/get-started/your-authtoken](https://dashboard.ngrok.com/get-started/your-authtoken)
3. Run the setup script:

```powershell
.\setup-ngrok-auth.ps1
```

When prompted, paste your ngrok authtoken.

### 3. Install Backend Dependencies

```bash
cd backend
npm install
cd ..
```

### 4. Configure Backend Environment

```bash
cd backend
copy env-template.txt .env
```

Edit `backend/.env` and update the `YOUR_NGROK_URL` placeholder (you'll get the actual URL after starting ngrok).

## Running the Application

### Step 1: Start the Backend Server

Open a PowerShell terminal and run:

```powershell
cd backend
.\start.ps1
```

Or manually:

```powershell
cd backend
node server.js
```

The server will start on `http://localhost:3000`.

### Step 2: Start ngrok Tunnel

Open a **new** PowerShell terminal and run:

```powershell
.\ngrok\ngrok.exe http 3000
```

You'll see output like:
```
Forwarding   https://xxxx-xxxx-xxxx.ngrok-free.app -> http://localhost:3000
```

**Copy the HTTPS URL** (e.g., `https://xxxx-xxxx-xxxx.ngrok-free.app`)

### Step 3: Update Configuration Files

Run the update script with your ngrok URL:

```powershell
.\update-ngrok-url.ps1 -NgrokUrl "https://xxxx-xxxx-xxxx.ngrok-free.app"
```

This updates:
- `backend/.env`
- `background/background.js`
- `manifest.json`

### Step 4: Visit ngrok URL Once

**Important**: Visit your ngrok URL once in a browser to accept the ngrok warning page:
```
https://xxxx-xxxx-xxxx.ngrok-free.app/api/notary/observe?host=github.com
```

Click "Visit Site" to accept the warning. This allows the extension to make API calls without the interstitial page.

### Step 5: Load the Extension in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **"Developer mode"** (toggle in top-right corner)
3. Click **"Load unpacked"**
4. Select the `GonePhishin` folder (the root directory of this project)
5. The extension should now appear in your Chrome toolbar

### Step 6: Test the Extension

1. Visit any HTTPS website (e.g., `https://github.com`)
2. Click the extension icon in the toolbar
3. You should see TLS verification results and notary consensus

## Development Workflow

### Making Changes

1. Edit files as needed
2. After changing `background/background.js` or `manifest.json`:
   - Go to `chrome://extensions/`
   - Click the **reload** icon on the extension card

### Testing Backend Changes

1. Make changes to backend files
2. Restart the backend server (Ctrl+C, then `node server.js`)
3. If ngrok URL changed, update configuration files

## Git Workflow

### Initial Setup (First Time)

```bash
# Initialize git repository (if not already done)
git init

# Add remote repository
git remote add origin <your-repo-url>

# Verify remote
git remote -v
```

### Daily Workflow

```bash
# Check status
git status

# Stage all changes
git add .

# Commit changes
git commit -m "Description of your changes"

# Push to remote
git push origin main
```

### Creating a New Branch

```bash
# Create and switch to new branch
git checkout -b feature/your-feature-name

# Make changes, then commit
git add .
git commit -m "Add new feature"

# Push branch to remote
git push origin feature/your-feature-name
```

### Updating from Remote

```bash
# Fetch latest changes
git fetch origin

# Merge changes
git merge origin/main

# Or use pull (fetch + merge)
git pull origin main
```

### Common Git Commands

```bash
# View commit history
git log

# View changes in working directory
git diff

# Discard local changes (be careful!)
git checkout -- <file>

# View branches
git branch

# Switch branches
git checkout <branch-name>
```

## Project Structure

```
GonePhishin/
├── backend/                 # Node.js backend server
│   ├── routes/
│   │   └── notary.js       # Notary API endpoint
│   ├── server.js           # Express server
│   ├── package.json        # Backend dependencies
│   └── .env                # Backend configuration (create from env-template.txt)
├── background/
│   └── background.js       # Extension service worker
├── popup/                   # Extension popup UI
├── heuristics/             # Phishing detection heuristics
├── icons/                  # Extension icons
├── manifest.json           # Extension manifest
├── ngrok/                 # ngrok executable
└── *.ps1                  # PowerShell setup scripts
```

## Troubleshooting

### Extension Not Working

1. Check that backend server is running on port 3000
2. Verify ngrok is running and forwarding to port 3000
3. Ensure you've visited the ngrok URL once in browser
4. Check Chrome console: `chrome://extensions/` → Click "service worker" link
5. Reload the extension

### Backend Connection Errors

1. Verify backend is running: `http://localhost:3000/health`
2. Check ngrok is running: Look for forwarding URL
3. Verify ngrok URL is updated in all config files
4. Check backend console for errors

### ngrok Issues

1. Ensure ngrok authtoken is configured: `.\ngrok\ngrok.exe config check`
2. Free tier ngrok URLs change on restart - update config files
3. Visit ngrok URL once in browser to accept warning

## Scripts Reference

- `setup-ngrok-auth.ps1` - Configure ngrok authtoken
- `backend/start.ps1` - Start backend server
- `update-ngrok-url.ps1` - Update ngrok URL in all config files
- `get-ngrok-url.ps1` - Get current ngrok URL from API

## License

MIT

## Support

For issues or questions, please open an issue on the repository.
