const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('rwscanner', {
  checkVersion: () => ipcRenderer.invoke('check-version'),
  startScan: (pin) => ipcRenderer.invoke('start-scan', pin),
  getSignatures: () => ipcRenderer.invoke('get-signatures'),
  submitResults: (data) => ipcRenderer.invoke('submit-results', data),
  close: () => ipcRenderer.invoke('close-window'),
  minimize: () => ipcRenderer.invoke('minimize-window')
});
