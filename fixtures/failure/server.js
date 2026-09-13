const { spawn } = require('child_process');
spawn(process.execPath, ['-e', 'setInterval(()=>{}, 1000)'], {stdio:'ignore'});
setInterval(() => {}, 1000);
