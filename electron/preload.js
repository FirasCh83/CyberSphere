const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('windowControls', {
  minimize: () => ipcRenderer.invoke('win:minimize'),
  maximize: () => ipcRenderer.invoke('win:maximize'),
  close: () => ipcRenderer.invoke('win:close'),
})
