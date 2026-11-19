// Standalone interactive chart checks: node --test tests/fmp-chart.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../assets/js/fmp-chart.js'), 'utf8');

function chartOptions(config) {
	const nodes = new Map();
	let options;
	const figure = {
		dataset: { stuhFmpChart: JSON.stringify(config) },
		querySelector(selector) {
			if (!nodes.has(selector)) {
				nodes.set(selector, { clientWidth: 1000, addEventListener() {} });
			}
			return nodes.get(selector);
		}
	};
	vm.runInNewContext(source, {
		document: { documentElement: { lang: 'en' }, querySelectorAll: () => [figure] },
		window: {
			uPlot: function (opts) { options = opts; },
			addEventListener() {}
		},
		ResizeObserver: class { observe() {} },
		Intl
	});
	const chart = { series: options.series.map(() => ({ show: true })) };
	return {
		chart,
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
