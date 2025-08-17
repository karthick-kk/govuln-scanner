(function(){
function startStream(e) {
	e.preventDefault();

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
		if (inner) { inner.dataset.timeSet = ''; inner.innerHTML = 'Total: - &nbsp; Passed: - &nbsp; Score: -'; }
		var top = document.getElementById('topSummary');
		if (top) top.style.display = 'none';
		var cur = document.getElementById('currentCheck');
		if (cur) cur.textContent = '';
	} catch (err) { /* ignore DOM errors */ }
	const form = document.getElementById('scanForm');
	const formData = new FormData(form);
	const params = new URLSearchParams();
	for (const pair of formData.entries()) { params.append(pair[0], pair[1]); }

	document.getElementById('loaderArea').style.display = 'block';
	document.getElementById('resultsArea').style.display = 'block';
	// adjust results offset to account for the visible fixed bars
	try { adjustResultsOffset(); } catch (err) { }

	// keep reference to event source so Stop can close it
	if (window._gv_evtSource) { try { window._gv_evtSource.close(); } catch(e){} }
	const evtSource = new EventSource('/stream?' + params.toString());
	window._gv_evtSource = evtSource;
	// show Stop button while scanning
	const stopBtn = document.getElementById('stopBtn');
	if (stopBtn) { stopBtn.style.display = 'inline-block'; }
	const tbody = document.querySelector('#liveResults tbody');
	let totalReceived = 0;
	let startTs = null;
	let timerId = null;

	function formatMs(ms) {
		const totalSec = Math.floor(ms/1000);
		const mm = Math.floor(totalSec/60).toString().padStart(2,'0');
		const ss = (totalSec % 60).toString().padStart(2,'0');
		return mm + ':' + ss;
	}

	function startTimer() {
		if (startTs) return;
		startTs = Date.now();
		document.getElementById('elapsed').textContent = '00:00';
		timerId = setInterval(function(){
			const now = Date.now();
			document.getElementById('elapsed').textContent = formatMs(now - startTs);
		}, 500);
	}

	function stopTimerAndSetTotal() {
		if (!startTs) return null;
		if (timerId) { clearInterval(timerId); timerId = null; }
		const totalMs = Date.now() - startTs;
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

	evtSource.addEventListener('check', function(e) {
		const data = JSON.parse(e.data);
		const tr = document.createElement('tr');
		const td1 = document.createElement('td'); td1.textContent = data.Controlid || '';
		const td2 = document.createElement('td'); td2.textContent = data.Check || '';
		const td3 = document.createElement('td');
		// use bootstrap label
		if (data.Status === 'FAIL') {
			td3.innerHTML = '<span class="label label-danger">' + (data.Status || '') + '</span>';
		} else {
			td3.innerHTML = '<span class="label label-success">' + (data.Status || '') + '</span>';
		}
		if (td3) td3.style.textAlign = 'center';
		tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
		tbody.appendChild(tr);
		document.getElementById('currentCheck').textContent = data.Check || '';
		totalReceived++;
		// update a crude progress bar (unknown total) by growing it a bit for each item
		const progress = Math.min(100, totalReceived * 3);
		document.getElementById('progressBar').style.width = progress + '%';
	});

	evtSource.addEventListener('started', function(e) {
		// begin elapsed timer
		startTimer();
	});

			// wire Stop button
			if (stopBtn) {
				stopBtn.onclick = function() {
					if (window._gv_evtSource) {
						window._gv_evtSource.close();
						window._gv_evtSource = null;
					}
					// stop timer and hide loader
					stopTimerAndSetTotal();
				  document.getElementById('loaderArea').style.display = 'none';
				  stopBtn.style.display = 'none';
				// show an interrupted message in the results area
				  try {
					  var resultsArea = document.getElementById('resultsArea');
					  if (resultsArea && !document.getElementById('stopMessage')) {
						  var msg = document.createElement('div');
						  msg.id = 'stopMessage';
						  msg.className = 'alert alert-warning';
						  msg.textContent = 'Scanning interrupted';
						  resultsArea.insertBefore(msg, resultsArea.firstChild);
					  }
					  var cur = document.getElementById('currentCheck');
					  if (cur) cur.textContent = 'Scanning interrupted';
				  } catch (err) { /* ignore DOM errors */ }
				// recompute spacing after hiding loader
				try { adjustResultsOffset(); } catch (err) { }
				}
			}

	evtSource.addEventListener('score', function(e) {
		const data = JSON.parse(e.data);
		document.getElementById('finalScore').innerHTML = '<b>Total:</b> '+data.Total+' &nbsp; <b>Passed:</b> '+data.Success+' &nbsp; <b>Score:</b> '+data.Percent;
		document.getElementById('progressBar').style.width = '100%';
		// populate fixed top summary and show it
		const top = document.getElementById('topSummary');
		const inner = document.getElementById('topSummaryInner');
		if (inner) {
			inner.innerHTML = '<b>Total:</b> '+data.Total+' &nbsp; <b>Passed:</b> '+data.Success+' &nbsp; <b>Score:</b> '+data.Percent;
		}
		if (top) { top.style.display = 'block'; }
		// adjust spacing now that top summary is visible
		try { adjustResultsOffset(); } catch (err) { }
		// stop timer and append total time
		stopTimerAndSetTotal();
	});

	evtSource.addEventListener('done', function(e) {
		evtSource.close();
		window._gv_evtSource = null;
		document.getElementById('currentCheck').textContent = 'Completed';
		// stop timer and ensure total time is set in top summary
		stopTimerAndSetTotal();
		document.getElementById('loaderArea').style.display = 'none';
		if (stopBtn) { stopBtn.style.display = 'none'; }
		try { adjustResultsOffset(); } catch (err) { }
	});

	evtSource.addEventListener('stopped', function(e) {
		// server acknowledged stop (client disconnect) — cleanup
		try { evtSource.close(); } catch (err) {}
		window._gv_evtSource = null;
		document.getElementById('currentCheck').textContent = 'Stopped';
		stopTimerAndSetTotal();
		document.getElementById('loaderArea').style.display = 'none';
		if (stopBtn) { stopBtn.style.display = 'none'; }
		// server-side stop: show interrupted message if not already present
		try {
			var resultsArea = document.getElementById('resultsArea');
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
		console.error('stream error', e);
		evtSource.close();
		document.getElementById('currentCheck').textContent = 'Error';
	});

	// Recompute results offset when window resizes or DOM is ready
	document.addEventListener('DOMContentLoaded', function(){ try { adjustResultsOffset(); } catch (err) {} });
	window.addEventListener('resize', function(){ try { adjustResultsOffset(); } catch (err) {} });
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

// wire up the form submit
var form = document.getElementById('scanForm');
if (form) form.addEventListener('submit', startStream, false);

})();
