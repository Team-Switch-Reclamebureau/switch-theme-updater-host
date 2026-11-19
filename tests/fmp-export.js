// Standalone rich-copy checks: node --test tests/fmp-export.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../assets/js/fmp-export.js'), 'utf8');

function reportCopy(write, supportsHtml = true) {
	let click;
	let selected = false;
	let focused = false;
	const button = {
		hidden: true,
		disabled: false,
		addEventListener(event, handler) { assert.equal(event, 'click'); click = handler; }
	};
	const preview = {
		innerHTML: '<p style="color:#ff0054"><strong>Opdracht 16780</strong></p>',
		focus() { focused = true; }
	};
	const text = { value: 'Opdracht 16780\nWebdevelopment\t1,00\n' };
	const status = { textContent: '', dataset: { success: 'Copied with formatting', failure: 'Copy failed; report selected for manual copy' } };
	const nodes = {
		'[data-stuh-fmp-copy-word]': button,
		'[data-stuh-fmp-word-preview]': preview,
		'[data-stuh-fmp-copy-status]': status
	};
	vm.runInNewContext(source, {
		document: {
			querySelector: selector => nodes[selector],
			getElementById: () => text,
			createRange: () => ({ selectNodeContents(node) { assert.equal(node, preview); } })
		},
		window: {
			ClipboardItem: supportsHtml ? class { constructor(data) { this.data = data; } } : undefined,
			getSelection: () => ({ removeAllRanges() {}, addRange() { selected = true; } })
		},
		navigator: { clipboard: write ? { write } : undefined },
		Blob
	});
	return { button, preview, text, status, click: () => click(), selected: () => selected, focused: () => focused };
}

test('copy sends HTML with inline styling and the exact TXT alternative', async () => {
	let items;
	let finish;
	const report = reportCopy(payload => {
		items = payload;
		return new Promise(resolve => { finish = resolve; });
	});
	assert.equal(report.button.hidden, false);
	const pending = report.click();
	assert.equal(report.button.disabled, true);
	assert.equal(report.status.textContent, '');
	assert.equal(items.length, 1);
	assert.equal(await items[0].data['text/html'].text(), report.preview.innerHTML);
	assert.equal(items[0].data['text/html'].type, 'text/html');
	assert.equal(await items[0].data['text/plain'].text(), report.text.value);
	finish();
	await pending;
	assert.equal(report.button.disabled, false);
	assert.equal(report.status.textContent, report.status.dataset.success);
	assert.equal(report.selected(), false);
});

test('clipboard denial selects the formatted report and gives manual-copy instructions, not false success', async () => {
	const report = reportCopy(() => Promise.reject(new Error('Permission denied')));
	await report.click();
	assert.equal(report.selected(), true);
	assert.equal(report.focused(), true);
	assert.equal(report.status.textContent, report.status.dataset.failure);
	assert.equal(report.button.disabled, false);
});

test('unsupported clipboard or HTML support selects the rich content without a plain-text-only fallback', async () => {
	for (const report of [
		reportCopy(undefined),
		reportCopy(() => { throw new Error('Must not call clipboard without HTML support'); }, false)
	]) {
		await report.click();
		assert.equal(report.selected(), true);
		assert.equal(report.status.textContent, report.status.dataset.failure);
		assert.equal(report.button.disabled, false);
	}
});

test('pages without export controls do not attempt clipboard setup', () => {
	vm.runInNewContext(source, {
		document: { querySelector: () => null, getElementById: () => null }
	});
});
