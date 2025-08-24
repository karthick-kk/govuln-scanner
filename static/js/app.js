(function() {
    'use strict';
    
    let evtSource = null;
    let startTime = null;
    let elapsedTimer = null;
    let totalChecks = 0;
    let currentCheck = 0;
    
    // DOM elements
    const scanForm = document.getElementById('scanForm');
    const keyfileInput = document.getElementById('keyfile');
    const keyHiddenInput = document.getElementById('key');
    const submitBtn = scanForm.querySelector('button[type="submit"]');
    const stopBtn = document.getElementById('stopBtn');
    const loaderArea = document.getElementById('loaderArea');
    const resultsArea = document.getElementById('resultsArea');
    const topSummary = document.getElementById('topSummary');
    const currentCheckSpan = document.getElementById('currentCheck');
    const elapsedSpan = document.getElementById('elapsed');
    const progressBar = document.getElementById('progressBar');
    const liveResults = document.getElementById('liveResults').getElementsByTagName('tbody')[0];
    const finalScore = document.getElementById('finalScore');
    
    // File reading for private key
    function readKeyFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = function(e) {
                const content = e.target.result;
                // Base64 encode the key content
                const encoded = btoa(content);
                resolve(encoded);
            };
            reader.onerror = function() {
                reject(new Error('Failed to read key file'));
            };
            reader.readAsText(file);
        });
    }
    
    // Handle keyfile input change
    if (keyfileInput) {
        keyfileInput.addEventListener('change', async function(e) {
            const file = e.target.files[0];
            if (file) {
                try {
                    const encodedKey = await readKeyFile(file);
                    keyHiddenInput.value = encodedKey;
                    console.log('Private key loaded and encoded');
                } catch (error) {
                    console.error('Error reading key file:', error);
                    alert('Error reading private key file: ' + error.message);
                    keyHiddenInput.value = '';
                }
            } else {
                keyHiddenInput.value = '';
            }
        });
    }
    
    function formatTime(seconds) {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return mins.toString().padStart(2, '0') + ':' + secs.toString().padStart(2, '0');
    }
    
    function formatMs(ms) {
        const totalSec = Math.floor(ms/1000);
        const mm = Math.floor(totalSec/60).toString().padStart(2,'0');
        const ss = (totalSec % 60).toString().padStart(2,'0');
        return mm + ':' + ss;
    }
    
    function updateElapsed() {
        if (startTime) {
            const elapsed = Date.now() - startTime;
            elapsedSpan.textContent = formatMs(elapsed);
        }
    }
    
    function startTimer() {
        startTime = Date.now();
        elapsedSpan.textContent = '00:00';
        elapsedTimer = setInterval(updateElapsed, 500);
    }
    
    function stopTimerAndSetTotal() {
        if (!startTime) return null;
        if (elapsedTimer) {
            clearInterval(elapsedTimer);
            elapsedTimer = null;
        }
        const totalMs = Date.now() - startTime;
        const totalStr = formatMs(totalMs);
        // append to top summary if present
        const inner = document.getElementById('topSummaryInner');
        if (inner) {
            // ensure we don't duplicate time if called multiple times
            if (!inner.dataset.timeSet) {
                inner.innerHTML = inner.innerHTML + ' &nbsp; <b>Scan Duration:</b> ' + totalStr;
                inner.dataset.timeSet = '1';
            }
        }
        return totalStr;
    }
    
    function stopTimer() {
        if (elapsedTimer) {
            clearInterval(elapsedTimer);
            elapsedTimer = null;
        }
    }
    
    // compute combined heights of visible fixed bars and set results container margin
    function adjustResultsOffset() {
        try {
            // measure all fixed elements that can overlap the content (navbar, controlBar, topSummary, loader)
            var nav = document.querySelector('.navbar-fixed-top');
            var controlBar = document.getElementById('controlBar');
            var topSummary = document.getElementById('topSummary');
            var loader = document.getElementById('loaderArea');
            var total = 0;
            if (nav) total += nav.getBoundingClientRect().height;
            if (controlBar) total += controlBar.getBoundingClientRect().height;
            if (topSummary && topSummary.style.display !== 'none') total += topSummary.getBoundingClientRect().height;
            if (loader && loader.style.display !== 'none') total += loader.getBoundingClientRect().height;
            // small gap so content isn't flush against the bars
            var gap = 6;
            var newPad = Math.max(100, Math.ceil(total + gap));
            // apply to body so normal flow is pushed down and nothing overlaps
            document.body.style.paddingTop = newPad + 'px';
            // ensure results container baseline margin is zero (JS controls spacing)
            var results = document.getElementById('resultsContainer');
            if (results) results.style.marginTop = '0px';
        } catch (err) { /* ignore measurement errors */ }
    }
    
    function resetUI() {
        // clean up any previous interrupted message or old results when starting a new scan
        try {
            var oldMsg = document.getElementById('stopMessage');
            if (oldMsg) oldMsg.remove();
            var oldTbody = document.querySelector('#liveResults tbody');
            if (oldTbody) oldTbody.innerHTML = '';
            var finalScore = document.getElementById('finalScore');
            if (finalScore) finalScore.innerHTML = '';
            var progress = document.getElementById('progressBar');
            if (progress) progress.style.width = '0%';
            var inner = document.getElementById('topSummaryInner');
            if (inner) { 
                inner.dataset.timeSet = ''; 
                inner.innerHTML = 'Total: - &nbsp; Passed: - &nbsp; Score: -'; 
            }
            var top = document.getElementById('topSummary');
            if (top) top.style.display = 'none';
            var cur = document.getElementById('currentCheck');
            if (cur) cur.textContent = '';
        } catch (err) { /* ignore DOM errors */ }
        
        loaderArea.style.display = 'none';
        resultsArea.style.display = 'none';
        topSummary.style.display = 'none';
        submitBtn.disabled = false;
        stopBtn.style.display = 'none';
        currentCheckSpan.textContent = 'Initializing';
        elapsedSpan.textContent = '00:00';
        progressBar.style.width = '0%';
        liveResults.innerHTML = '';
        finalScore.innerHTML = '';
        totalChecks = 0;
        currentCheck = 0;
        stopTimer();
    }
    
    function addResultRow(data) {
        const tr = document.createElement('tr');
        const td1 = document.createElement('td'); 
        td1.textContent = data.Controlid || '';
        const td2 = document.createElement('td'); 
        td2.textContent = data.Check || '';
        const td3 = document.createElement('td');
        
        // use bootstrap label styling like the original
        if (data.Status === 'FAIL') {
            td3.innerHTML = '<span class="label label-danger">' + (data.Status || '') + '</span>';
        } else if (data.Status === 'PASS') {
            td3.innerHTML = '<span class="label label-success">' + (data.Status || '') + '</span>';
        } else {
            td3.innerHTML = '<span class="label label-default">' + (data.Status || '') + '</span>';
        }
        td3.style.textAlign = 'center';
        
        tr.appendChild(td1); 
        tr.appendChild(td2); 
        tr.appendChild(td3);
        liveResults.appendChild(tr);
        
        currentCheck++;
        currentCheckSpan.textContent = data.Check || '';
        
        // Dynamic progress bar that grows with each check (crude but effective like original)
        const progress = Math.min(100, currentCheck * 3);
        progressBar.style.width = progress + '%';
        
        // Scroll to bottom
        resultsArea.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }
    
    function startStream(formData) {
        const params = new URLSearchParams();
        for (const [key, value] of formData.entries()) {
            params.append(key, value);
        }
        
        const url = `/stream?${params.toString()}`;
        evtSource = new EventSource(url);
        window._gv_evtSource = evtSource; // Global reference for stop button
        
        evtSource.addEventListener('started', function(e) {
            console.log('Scan started:', e.data);
            loaderArea.style.display = 'block';
            resultsArea.style.display = 'block';
            submitBtn.disabled = true;
            stopBtn.style.display = 'inline-block';
            startTimer();
            // adjust results offset to account for the visible fixed bars
            try { adjustResultsOffset(); } catch (err) { }
        });
        
        evtSource.addEventListener('check', function(e) {
            try {
                const data = JSON.parse(e.data);
                addResultRow(data);
            } catch (err) {
                console.error('Error parsing check data:', err);
            }
        });
        
        evtSource.addEventListener('score', function(e) {
            try {
                const data = JSON.parse(e.data);
                totalChecks = parseInt(data.Total) || 0;
                const passed = parseInt(data.Success) || 0;
                const percent = parseFloat(data.Percent) || 0;
                
                finalScore.innerHTML = '<b>Total:</b> '+data.Total+' &nbsp; <b>Passed:</b> '+data.Success+' &nbsp; <b>Score:</b> '+data.Percent+'%';
                progressBar.style.width = '100%';
                
                // populate fixed top summary and show it
                const inner = document.getElementById('topSummaryInner');
                if (inner) {
                    inner.innerHTML = '<b>Total:</b> '+data.Total+' &nbsp; <b>Passed:</b> '+data.Success+' &nbsp; <b>Score:</b> '+data.Percent+'%';
                }
                topSummary.style.display = 'block';
                
                // adjust spacing now that top summary is visible
                try { adjustResultsOffset(); } catch (err) { }
                // stop timer and append total time
                stopTimerAndSetTotal();
            } catch (err) {
                console.error('Error parsing score data:', err);
            }
        });
        
        evtSource.addEventListener('done', function(e) {
            console.log('Scan finished:', e.data);
            evtSource.close();
            window._gv_evtSource = null;
            currentCheckSpan.textContent = 'Completed';
            // stop timer and ensure total time is set in top summary
            stopTimerAndSetTotal();
            loaderArea.style.display = 'none';
            stopBtn.style.display = 'none';
            try { adjustResultsOffset(); } catch (err) { }
        });
        
        evtSource.addEventListener('stopped', function(e) {
            console.log('Scan stopped:', e.data);
            // server acknowledged stop (client disconnect) — cleanup
            try { evtSource.close(); } catch (err) {}
            window._gv_evtSource = null;
            currentCheckSpan.textContent = 'Stopped';
            stopTimerAndSetTotal();
            loaderArea.style.display = 'none';
            stopBtn.style.display = 'none';
            // server-side stop: show interrupted message if not already present
            try {
                if (resultsArea && !document.getElementById('stopMessage')) {
                    var msg = document.createElement('div');
                    msg.id = 'stopMessage';
                    msg.className = 'alert alert-warning';
                    msg.textContent = 'Scanning interrupted';
                    resultsArea.insertBefore(msg, resultsArea.firstChild);
                }
            } catch (err) { }
            try { adjustResultsOffset(); } catch (err) { }
        });
        
        evtSource.addEventListener('error', function(e) {
            try {
                const data = JSON.parse(e.data);
                console.error('Scan error:', data);
                alert('Scan error: ' + data);
            } catch {
                console.error('Stream error occurred', e);
                alert('An error occurred during scanning. Please check the logs.');
            }
            evtSource.close();
            currentCheckSpan.textContent = 'Error';
            stopStream();
        });
        
        evtSource.onerror = function(e) {
            console.error('EventSource error:', e);
            stopStream();
        };
    }
    
    function stopStream() {
        if (evtSource) {
            evtSource.close();
            evtSource = null;
        }
        if (window._gv_evtSource) {
            window._gv_evtSource.close();
            window._gv_evtSource = null;
        }
        submitBtn.disabled = false;
        stopBtn.style.display = 'none';
        stopTimer();
    }
    
    // Form submission handler
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(scanForm);
            const hostname = formData.get('name');
            const username = formData.get('user');
            const password = formData.get('password');
            const keyData = formData.get('key');
            
            if (!hostname || !username) {
                alert('Please provide hostname and username');
                return;
            }
            
            if (!password && !keyData) {
                alert('Please provide either a password or private key');
                return;
            }
            
            resetUI();
            startStream(formData);
        });
    }
    
    // Stop button handler
    if (stopBtn) {
        stopBtn.addEventListener('click', function() {
            if (window._gv_evtSource) {
                window._gv_evtSource.close();
                window._gv_evtSource = null;
            }
            // stop timer and hide loader
            stopTimerAndSetTotal();
            loaderArea.style.display = 'none';
            stopBtn.style.display = 'none';
            // show an interrupted message in the results area
            try {
                if (resultsArea && !document.getElementById('stopMessage')) {
                    var msg = document.createElement('div');
                    msg.id = 'stopMessage';
                    msg.className = 'alert alert-warning';
                    msg.textContent = 'Scanning interrupted';
                    resultsArea.insertBefore(msg, resultsArea.firstChild);
                }
                currentCheckSpan.textContent = 'Scanning interrupted';
            } catch (err) { /* ignore DOM errors */ }
            // recompute spacing after hiding loader
            try { adjustResultsOffset(); } catch (err) { }
            stopStream();
        });
    }
    
    // Cleanup on page unload
    window.addEventListener('beforeunload', function() {
        stopStream();
    });
    
    // Recompute results offset when window resizes or DOM is ready
    document.addEventListener('DOMContentLoaded', function(){ 
        try { adjustResultsOffset(); } catch (err) {} 
    });
    window.addEventListener('resize', function(){ 
        try { adjustResultsOffset(); } catch (err) {} 
    });
})();
