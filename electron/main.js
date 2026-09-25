const { app, BrowserWindow, ipcMain } = require('electron')
const { spawn } = require('child_process')
const path = require('path')

let pythonProcess = null

// prefer the project venv so backend deps (fastapi, docker, openai...) resolve
function resolvePython() {
  const projectRoot = path.join(__dirname, '..')
  const venvPy = process.platform === 'win32'
    ? path.join(projectRoot, 'venv', 'Scripts', 'python.exe')
    : path.join(projectRoot, 'venv', 'bin', 'python')
  try {
    require('fs').accessSync(venvPy)
    return venvPy
  } catch {
    return 'python'
  }
}

function startPythonBackend() {
  const projectRoot = path.join(__dirname, '..')
  const serverPath = path.join(projectRoot, 'server.py')
  const py = resolvePython()

  console.log('[Electron] launching backend with:', py, serverPath)

  pythonProcess = spawn(py, [serverPath], {
    cwd: projectRoot,
    env: { ...process.env, PYTHONUNBUFFERED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  pythonProcess.stdout.on('data', d => console.log('[Python]', d.toString()))
  pythonProcess.stderr.on('data', d => console.error('[Python ERR]', d.toString()))
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 980,
    minHeight: 620,
    frame: false,
    backgroundColor: '#102546',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  })

  // wire up frameless window controls
  const controls = {
    minimize: (s) => s.minimize(),
    maximize: (s) => (s.isMaximized() ? s.unmaximize() : s.maximize()),
    close: (s) => s.close(),
  }
  for (const [action, fn] of Object.entries(controls)) {
    ipcMain.handle(`win:${action}`, () => fn(win))
  }

  // In dev (running via `electron .`, i.e. not packaged) load the live Vite
  // dev server so edits hot-reload. Packaged builds load the bundled dist.
  if (!app.isPackaged) {
    win.loadURL('http://localhost:5173')
  } else {
    win.loadFile(path.join(__dirname, '../dist/index.html'))
  }
}

app.whenReady().then(() => {
  startPythonBackend()
  setTimeout(createWindow, 2000)
})

app.on('window-all-closed', () => {
  if (pythonProcess) pythonProcess.kill()
  if (process.platform !== 'darwin') app.quit()
})
