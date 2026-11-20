// Standalone interactive chart checks: node --test tests/fmp-chart.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../assets/js/fmp-chart.js'), 'utf8');

function chartOptions(config) {
	const nodes = new Map();
	const legend = { children: [], appendChild(child) { this.children.push(child); } };
	let options;
	let data;
	const barPaths = () => {};
	const uPlot = function (opts, values) { options = opts; data = values; };
	uPlot.paths = { bars: () => barPaths, linear: () => (...args) => args.slice(2) };
	uPlot.pxRatio = 2;
	const figure = {
		dataset: { stuhFmpChart: JSON.stringify(config) },
		querySelector(selector) {
			if (!nodes.has(selector)) {
				nodes.set(selector, { clientWidth: 1000, addEventListener() {}, querySelector: () => legend });
			}
			return nodes.get(selector);
		}
	};
	vm.runInNewContext(source, {
		document: {
			documentElement: { lang: 'en' }, querySelectorAll: () => [figure],
			createElement: tag => ({ tag, children: [], appendChild(child) { this.children.push(child); } })
		},
		window: {
			uPlot,
			addEventListener() {}
		},
		ResizeObserver: class { observe() {} },
		Intl
	});
	const chart = { series: options.series.map(series => ({ show: series.show !== false })), bbox: { width: 2000 } };
	return {
		chart,
		options,
		data,
		barPaths,
		nodes,
		legend,
		range(min, max) {
			options.scales.x.range(chart, min, max);
			return options.scales.y.range(chart);
		}
	};
}

function budgetConfig(unit = 'eur') {
	return {
		unit,
		series: [
			{ points: [[0, 12000000], [1000, 12000000]] },
			{ points: [[0, 0], [1000, 12000000]] },
			{ points: [[0, 0], [900, 10400000]] },
			{ points: [[0, 0], [900, 11100000]] }
		]
	};
}

test('zoom fits visible line segments, even between monthly samples, and reset restores full bounds', () => {
	const plot = chartOptions(budgetConfig());
	const full = plot.range(0, 1000);
	const zoomed = plot.range(810, 820);
	assert.ok(zoomed[0] > 90000 && zoomed[0] < 93600, 'Lower bound includes interpolated actual usage without forcing zero');
	assert.ok(zoomed[1] > 120000 && zoomed[1] < 125000, 'Budget line remains visible with padding');
	assert.ok(zoomed[1] - zoomed[0] < (full[1] - full[0]) / 3);
	const restored = plot.range(0, 1000);
	assert.equal(restored[0], full[0]);
	assert.equal(restored[1], full[1]);
});

test('hidden series and expired usage do not constrain the visible Y range', () => {
	const plot = chartOptions(budgetConfig());
	plot.chart.series[1].show = false;
	const zoomed = plot.range(810, 820);
	assert.ok(zoomed[1] < 110000, 'Hiding the budget line allows a tighter range');
	const afterUsage = plot.range(950, 960);
	assert.ok(afterUsage[0] > 113000, 'Recorded and invoiced lines are not extrapolated beyond their last sample');
	plot.chart.series.forEach(series => { series.show = false; });
	assert.equal(plot.range(950, 960)[0], null);
});

test('default-hidden series remain in the legend without affecting chart scaling', () => {
	const config = budgetConfig();
	config.series[0].show = false;
	config.series[3].show = false;
	const plot = chartOptions(config);
	assert.equal(plot.options.series.length, 5, 'Keep hidden series available in the interactive legend');
	assert.equal(plot.options.series[1].show, false);
	assert.equal(plot.options.series[4].show, false);
	assert.equal(plot.options.series[2].show, true);
	assert.equal(plot.options.series[3].show, true);
	assert.ok(plot.range(100, 200)[1] < 30000, 'Initially hidden budget and invoices do not expand the range');
	plot.chart.series[1].show = true;
	assert.ok(plot.range(100, 200)[1] > 120000, 'Showing the budget through the legend restores its scale contribution');
	assert.equal(plot.nodes.get('[data-stuh-fmp-static-legend]').hidden, true, 'Do not show duplicate legends after the interactive plot loads');
});

test('zoom reset is shown only while zoomed and hides again at the full period', () => {
	const plot = chartOptions(budgetConfig());
	const reset = plot.nodes.get('[data-stuh-fmp-reset]');
	const update = plot.options.hooks.setScale[0];
	plot.chart.scales = { x: { min: 0, max: 1000 } };
	update(plot.chart, 'x');
	assert.equal(reset.hidden, true);
	assert.equal(reset.disabled, true);
	plot.chart.scales.x = { min: 100, max: 200 };
	update(plot.chart, 'x');
	assert.equal(reset.hidden, false);
	assert.equal(reset.disabled, false);
	plot.chart.scales.x = { min: 0, max: 1000 };
	update(plot.chart, 'x');
	assert.equal(reset.hidden, true);
});

test('flat, zero and negative histories keep a finite padded range in either unit', () => {
	for (const unit of ['eur', 'hours']) {
		for (const value of [0, -9000, 9000000]) {
			const plot = chartOptions({ unit, series: [{ points: [[0, value], [1000, value]] }] });
			const range = plot.range(400, 600);
			const displayed = value / (unit === 'hours' ? 9000 : 100);
			assert.ok(Number.isFinite(range[0]) && Number.isFinite(range[1]));
			assert.ok(range[0] < displayed && range[1] > displayed);
		}
	}
});

test('monthly bars use native bar paths, include zero and negative corrections, and do not interpolate', () => {
	for (const unit of ['eur', 'hours']) {
		const plot = chartOptions({
			unit,
			series: [
				{ points: [[0, 900000], [1000, 900000]] },
				{ type: 'bars', points: [[200, 18000], [700, -9000]], periods: [[100, 300], [600, 800]] }
			]
		});

		const bar = plot.options.series[2];
		assert.equal(bar.paths, plot.barPaths);
		assert.equal(bar.spanGaps, false);
		assert.equal(plot.data[2][0], undefined, 'Other line timestamps must not shrink native bar widths');
		assert.equal(plot.data[2][1], unit === 'hours' ? 2 : 180);
		assert.equal(plot.data[2][2], unit === 'hours' ? -1 : -90);
		assert.match(bar.value(null, plot.data[2][1]), /2\.00 h/);
		plot.chart.series[1].show = false;
		const negative = plot.range(610, 620);
		assert.ok(negative[0] < -1 && negative[1] > 0, 'Zoom keeps negative bars and their zero baseline visible');
		assert.equal(plot.range(400, 500)[0], null, 'No invented line joins monthly bars');
		plot.chart.series[2].show = false;
		assert.equal(plot.range(100, 300)[0], null, 'Hidden bars do not affect zoom scaling');
	}
});

test('month labels and provisional actual line keep only the final segment dotted', () => {
	const august = Date.UTC(2026, 7, 1) / 1000;
	const september = Date.UTC(2026, 8, 1) / 1000;
	const october = Date.UTC(2026, 9, 1) / 1000;
	const plot = chartOptions({ unit: 'hours', series: [
		{ points: [[august, 90000], [october, 90000]] },
		{ provisional: true, stroke: '#d63638', points: [[august, 0], [september, 9000], [october, 18000]] }
	] });
	assert.equal(plot.options.series[0].value(null, september), 'Sep 2026');
	assert.deepEqual(Array.from(plot.options.axes[0].values({}, [september])), ['Sep 2026']);
	assert.deepEqual(Array.from(plot.options.axes[0].splits(plot.chart, 0, september, october)), [september, october]);
	assert.deepEqual(Array.from(plot.options.series[2].paths({}, 2, 0, 2)), [0, 1]);
	assert.deepEqual(Array.from(plot.options.series[2].paths({}, 2, 2, 2)), [1, 1]);
	const calls = [];
	const ctx = Object.fromEntries(['save', 'beginPath', 'rect', 'clip', 'setLineDash', 'moveTo', 'lineTo', 'stroke', 'restore'].map(name => [name, (...args) => calls.push([name, ...args])]));
	Object.assign(plot.chart, { ctx, bbox: { left: 0, top: 0, width: 100, height: 100 }, valToPos: value => value });
	plot.options.hooks.drawSeries[0](plot.chart, 2);
	assert.deepEqual(Array.from(calls.find(call => call[0] === 'setLineDash')[1]), [4, 8]);
	assert.deepEqual(calls.find(call => call[0] === 'moveTo'), ['moveTo', september, 1]);
	assert.deepEqual(calls.find(call => call[0] === 'lineTo'), ['lineTo', october, 2]);
	plot.chart.series[2].show = false;
	calls.length = 0;
	plot.options.hooks.drawSeries[0](plot.chart, 2);
	assert.equal(calls.length, 0, 'Hiding actual time also hides the dotted segment');
});

test('variance shading draws both colors in chart units and follows line visibility', () => {
	for (const unit of ['eur', 'hours']) {
		const config = budgetConfig(unit);
		config.variance = [
			{ over: true, points: [[0, 0], [500, 9000], [500, 18000], [0, 9000]] },
			{ over: false, points: [[500, 9000], [1000, 18000], [1000, 0], [500, 9000]] }
		];
		const plot = chartOptions(config);
		const fills = [];
		const positions = [];
		const ctx = {
			save() {}, restore() {}, beginPath() {}, rect() {}, clip() {}, closePath() {},
			moveTo(x, y) { positions.push([x, y]); },
			lineTo(x, y) { positions.push([x, y]); },
			fill() { fills.push(this.fillStyle); }
		};
		Object.assign(plot.chart, { ctx, bbox: { left: 0, top: 0, width: 100, height: 100 }, valToPos: value => value });
		plot.options.hooks.drawAxes[0](plot.chart);
		assert.deepEqual(fills, ['rgba(214,54,56,0.16)', 'rgba(0,138,32,0.16)']);
		assert.equal(positions[1][1], unit === 'hours' ? 1 : 90);
		for (const index of [2, 3]) {
			fills.length = 0;
			plot.chart.series[index].show = false;
			plot.options.hooks.drawAxes[0](plot.chart);
			assert.equal(fills.length, 0, 'No shading when either boundary line is hidden');
			plot.chart.series[index].show = true;
		}
	}
});

test('secondary counts have a right axis independent of budget units, missing values and zoom', () => {
	for (const unit of ['eur', 'hours']) {
		const config = budgetConfig(unit);
		config.secondaryLabel = 'Form entries';
		config.series.push({
			scale: 'secondary',
			points: [[0, 20], [400, 0], [600, null], [1000, 9000000]]
		});

		const baseline = chartOptions(budgetConfig(unit));
		const plot = chartOptions(config);
		assert.equal(plot.options.axes[2].side, 1);
		assert.equal(plot.options.axes[2].scale, 'secondary');
		assert.equal(plot.options.series[5].scale, 'secondary');
		assert.equal(plot.options.series[5].spanGaps, false, 'Do not join lines across missing reports');
		assert.equal(plot.data[5][0], 20);
		assert.equal(plot.data[5][1], 0);
		assert.equal(plot.data[5][2], null, 'Missing is not coerced to zero');
		assert.equal(plot.options.series[5].value(null, 20), '20', 'Counts are never currency or hour equivalents');
		assert.deepEqual(Array.from(plot.range(0, 1000)), Array.from(baseline.range(0, 1000)), 'Large counts do not expand the budget scale');
		const full = plot.options.scales.secondary.range(plot.chart);
		plot.range(100, 200);
		const zoomed = plot.options.scales.secondary.range(plot.chart);
		assert.ok(zoomed[1] < full[1] / 1000, 'Secondary scale fits the zoomed month range');
		plot.range(700, 800);
		assert.equal(plot.options.scales.secondary.range(plot.chart)[0], null, 'No interpolation across a missing monthly report');
		plot.range(0, 1000);
		plot.chart.series[5].show = false;
		assert.equal(plot.options.scales.secondary.range(plot.chart)[0], null, 'Legend visibility also affects the right scale');
	}
});

test('month ticks fit the chart width without removing any data points', () => {
	const points = Array.from({ length: 13 }, (_, index) => [Date.UTC(2026, index, 1) / 1000, index * 9000]);
	const plot = chartOptions({ unit: 'hours', series: [{ points }] });
	const min = points[0][0];
	const max = points.at(-1)[0];
	plot.chart.bbox.width = 720;
	const ticks = Array.from(plot.options.axes[0].splits(plot.chart, 0, min, max));
	assert.ok(ticks.length < points.length);
	for (let index = 1; index < ticks.length; index++) {
		assert.ok((ticks[index] - ticks[index - 1]) / (max - min) * 360 >= 100, 'Month labels have at least 100 CSS pixels between them');
	}
	assert.equal(plot.data[0].length, points.length, 'Only tick labels are thinned, not monthly samples');
	const zoomed = Array.from(plot.options.axes[0].splits(plot.chart, 0, points[0][0], points[1][0]));
	assert.equal(zoomed.length, 2, 'Zoom restores monthly detail when it fits');
});

test('release squares use chart coordinates, follow line visibility and expose nearby hover details', () => {
	for (const unit of ['eur', 'hours']) {
		const config = budgetConfig(unit);
		config.series[2].stroke = '#d63638';
		config.series[2].releases = [{ timestamp: 450, value: 9000, label: 'owner/theme v1 - 2026-01-15 UTC' }];
		const plot = chartOptions(config);
		const calls = [];
		const ctx = Object.fromEntries(['save', 'beginPath', 'rect', 'clip', 'fillRect', 'strokeRect', 'restore'].map(name => [name, (...args) => calls.push([name, ...args])]));
		const y = unit === 'hours' ? 1 : 90;
		Object.assign(plot.chart, {
			ctx, bbox: { left: 0, top: 0, width: 100, height: 100 },
			valToPos: value => value, over: {}, cursor: { left: 450, top: y }
		});

		plot.options.hooks.draw[0](plot.chart);
		assert.deepEqual(calls.find(call => call[0] === 'fillRect'), ['fillRect', 442, y - 8, 16, 16]);
		assert.equal(ctx.fillStyle, '#d63638');
		assert.ok(calls.some(call => call[0] === 'clip'), 'Clip squares to the zoomed plot bounds');
		plot.options.hooks.setCursor[0](plot.chart);
		assert.equal(plot.chart.over.title, config.series[2].releases[0].label);
		plot.chart.cursor.left = 470;
		plot.options.hooks.setCursor[0](plot.chart);
		assert.equal(plot.chart.over.title, '', 'Clear hover details away from squares');
		plot.chart.series[3].show = false;
		calls.length = 0;
		plot.options.hooks.draw[0](plot.chart);
		assert.equal(calls.length, 0, 'Hiding recorded time also hides its release squares');
		plot.chart.cursor.left = 450;
		plot.options.hooks.setCursor[0](plot.chart);
		assert.equal(plot.chart.over.title, '');
	}
});

test('release legend key is descriptive rather than another series toggle', () => {
	const config = budgetConfig();
	config.releaseLabel = 'Theme releases';
	const plot = chartOptions(config);
	assert.equal(plot.legend.children.length, 1);
	assert.equal(plot.legend.children[0].className, 'stuh-fmp-legend-releases');
	assert.equal(plot.legend.children[0].children[0].textContent, 'Theme releases');
	assert.equal(plot.options.series.length, 5, 'Do not add a dummy series for the release key');
	assert.equal(chartOptions(budgetConfig()).legend.children.length, 0, 'Omit the key when there are no plotted releases');
});
