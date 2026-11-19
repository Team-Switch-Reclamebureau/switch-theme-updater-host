(function () {
	'use strict';

	var button = document.querySelector('[data-stuh-fmp-copy-word]');
	var preview = document.querySelector('[data-stuh-fmp-word-preview]');
	var text = document.getElementById('stuh-fmp-export-preview');
	var status = document.querySelector('[data-stuh-fmp-copy-status]');
	if (!button || !preview || !text || !status) {
		return;
	}

	var selectReport = function () {
		preview.focus();
		var range = document.createRange();
		range.selectNodeContents(preview);
		var selection = window.getSelection();
		selection.removeAllRanges();
		selection.addRange(range);
		status.textContent = status.dataset.failure;
	};

	button.hidden = false;
	button.addEventListener('click', async function () {
		status.textContent = '';
		if (!navigator.clipboard || typeof navigator.clipboard.write !== 'function' || typeof window.ClipboardItem !== 'function') {
			selectReport();
			return;
		}
		button.disabled = true;
		try {
			await navigator.clipboard.write([new window.ClipboardItem({
				'text/html': new Blob([preview.innerHTML], { type: 'text/html' }),
				'text/plain': new Blob([text.value], { type: 'text/plain' })
			})]);
			status.textContent = status.dataset.success;
		} catch (error) {
			selectReport();
		} finally {
			button.disabled = false;
		}
	});
}());
