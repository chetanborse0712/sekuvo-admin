const SERVER = 'https://sekuvo-admin.onrender.com';

document.getElementById('usbBtn').onclick = async function() {
  try {
    const [fileHandle] = await window.showOpenFilePicker();
    const file = await fileHandle.getFile();
    const content = await file.text();
    const keyData = JSON.parse(content);

    const response = await fetch(SERVER + '/api/verify-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: keyData.key,
        deviceId: keyData.deviceId,
        machine: keyData.machine,
        expiresAt: keyData.expiresAt
      })
    });

    const data = await response.json();

    if (data.success) {
      // sessionStorage — browser band hote hi delete
      sessionStorage.setItem('adminToken', data.token);
      sessionStorage.setItem('deviceName', data.deviceName);
      
      // Server se admin panel load karo
      window.location.href = `https://sekuvo-admin.onrender.com/admin.html`;
    } else {
      alert('Access Denied: ' + data.message);
    }
  } catch(e) {
    alert('Error: ' + e.message);
  }
};