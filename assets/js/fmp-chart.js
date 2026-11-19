(function () {
	'use strict';

	document.querySelectorAll('[data-stuh-fmp-chart]').forEach(function (figure) {
		var error = figure.querySelector('[data-stuh-fmp-chart-error]');
		if (typeof window.uPlot !== 'function') {
			error.hidden = false;
			return;
		}

		var config = JSON.parse(figure.dataset.stuhFmpChart);
		var interactive = figure.querySelector('[data-stuh-fmp-interactive]');
		var host = figure.querySelector('[data-stuh-fmp-plot]');
		var reset = figure.querySelector('[data-stuh-fmp-reset]');
		var range = figure.querySelector('[data-stuh-fmp-range]');
		var divisor = config.unit === 'hours' ? 9000 : 100;
		var locale = document.documentElement.lang || undefined;
		var numbers = new Intl.NumberFormat(locale, {
			minimumFractionDigits: 2,
			maximumFractionDigits: 2,
			style: config.unit === 'hours' ? 'decimal' : 'currency',
			currency: 'EUR'
		});
		var hours = new Intl.NumberFormat(locale, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
		var months = new Intl.DateTimeFormat(locale, { month: 'short', year: 'numeric', timeZone: 'UTC' });
		var formatValue = function (value) {
			return value == null ? '-' : numbers.format(value) + (config.unit === 'hours' ? ' h' : '');
		};
		var timestamps = Array.from(new Set(config.series.flatMap(function (series) {
			return series.points.map(function (point) { return point[0]; });
		}))).sort(function (a, b) { return a - b; });
		var fullMin = timestamps[0];
		var fullMax = timestamps[timestamps.length - 1];
		var visibleMin = fullMin;
		var visibleMax = fullMax;
		var yRange = function (chart) {
			var minimum = Infinity;
			var maximum = -Infinity;
			var include = function (value) {
				minimum = Math.min(minimum, value / divisor);
				maximum = Math.max(maximum, value / divisor);
			};
			config.series.forEach(function (item, index) {
				if (!chart.series[index + 1].show) {
					return;
				}
				item.points.forEach(function (point, pointIndex) {
					if (item.type === 'bars') {
						var period = item.periods[pointIndex];
						if (period[1] >= visibleMin && period[0] <= visibleMax) {
							include(0);
							include(point[1]);
						}
						return;
					}
					if (point[0] >= visibleMin && point[0] <= visibleMax) {
						include(point[1]);
					}
					if (pointIndex === 0) {
						return;
					}
					var previous = item.points[pointIndex - 1];
					var start = Math.max(previous[0], visibleMin);
					var end = Math.min(point[0], visibleMax);
					if (start <= end && point[0] > previous[0]) {
						// Include the visible line even when zoomed between monthly points.
						var slope = (point[1] - previous[1]) / (point[0] - previous[0]);
						include(previous[1] + slope * (start - previous[0]));
						include(previous[1] + slope * (end - previous[0]));
					}
				});
			});
			if (minimum === Infinity) {
				return [null, null];
			}
			var padding = maximum === minimum ? Math.max(Math.abs(maximum) * 0.01, 1) : Math.max((maximum - minimum) * 0.05, 0.01);
			return [minimum - padding, maximum + padding];
		};
		var data = [timestamps];
		var series = [{
			label: config.dateLabel,
			value: function (plot, value) { return value == null ? '-' : months.format(new Date(value * 1000)); }
		}];
		config.series.forEach(function (item, index) {
			var bar = item.type === 'bars';
			var paths;
			if (item.provisional) {
				var linear = window.uPlot.paths.linear();
				var previousTime = item.points[item.points.length - 2][0];
				paths = function (chart, seriesIndex, start, end) {
					var lastSolid = timestamps.indexOf(previousTime);
					return linear(chart, seriesIndex, Math.min(start, lastSolid), Math.min(end, lastSolid));
				};
			}
			var values = new Map(item.points);
			data.push(timestamps.map(function (timestamp) {
				if (index === 0) {
					return item.points[0][1] / divisor;
				}
				return values.has(timestamp) ? values.get(timestamp) / divisor : (bar ? undefined : null);
			}));
			series.push({
				label: item.label,
				stroke: item.stroke,
				dash: item.dash,
				width: bar ? 1 : 2,
				fill: bar ? item.fill : undefined,
				paths: bar ? window.uPlot.paths.bars({ size: [0.65, 40] }) : paths,
				spanGaps: !bar,
				points: { show: false },
				value: function (plot, value) {
					return formatValue(value) + (bar && config.unit !== 'hours' && value != null ? ' (' + hours.format(value / 90) + ' h)' : '');
				}
			});
		});
		interactive.hidden = false;
		var plot = new window.uPlot({
			width: host.clientWidth,
			height: 420,
			series: series,
			tzDate: function (timestamp) { return window.uPlot.tzDate(new Date(timestamp * 1000), 'Etc/UTC'); },
			scales: {
				x: {
					time: true,
					range: function (chart, min, max) {
						visibleMin = min;
						visibleMax = max;
						return [min, max];
					}
				},
				y: { range: yRange }
			},
			axes: [{
				label: config.xLabel,
				space: 100,
				splits: function (chart, index, min, max) {
					return timestamps.filter(function (timestamp) { return timestamp >= min && timestamp <= max; });
				},
				values: function (chart, ticks) {
					return ticks.map(function (tick) { return months.format(new Date(tick * 1000)); });
				}
			}, {
				label: config.yLabel,
				size: 100,
				values: function (chart, ticks) { return ticks.map(formatValue); }
			}],
			cursor: { drag: { x: true, y: false, setScale: true, dist: 10 } },
			hooks: {
				drawAxes: [function (chart) {
					if (!config.variance || !chart.series[2].show || !chart.series[3].show) {
						return;
					}
					var ctx = chart.ctx;
					ctx.save();
					ctx.beginPath();
					ctx.rect(chart.bbox.left, chart.bbox.top, chart.bbox.width, chart.bbox.height);
					ctx.clip();
					config.variance.forEach(function (region) {
						ctx.beginPath();
						region.points.forEach(function (point, index) {
							var x = chart.valToPos(point[0], 'x', true);
							var y = chart.valToPos(point[1] / divisor, 'y', true);
							if (index === 0) {
								ctx.moveTo(x, y);
							} else {
								ctx.lineTo(x, y);
							}
						});
						ctx.closePath();
						ctx.fillStyle = region.over ? 'rgba(214,54,56,0.16)' : 'rgba(0,138,32,0.16)';
						ctx.fill();
					});
					ctx.restore();
				}],
				drawSeries: [function (chart, seriesIndex) {
					var item = config.series[seriesIndex - 1];
					if (!item || !item.provisional || !chart.series[seriesIndex].show) {
						return;
					}
					var points = item.points.slice(-2);
					var ctx = chart.ctx;
					var ratio = window.uPlot.pxRatio;
					ctx.save();
					ctx.beginPath();
					ctx.rect(chart.bbox.left, chart.bbox.top, chart.bbox.width, chart.bbox.height);
					ctx.clip();
					ctx.beginPath();
					ctx.strokeStyle = item.stroke;
					ctx.lineWidth = 2 * ratio;
					ctx.setLineDash([2 * ratio, 4 * ratio]);
					ctx.moveTo(chart.valToPos(points[0][0], 'x', true), chart.valToPos(points[0][1] / divisor, 'y', true));
					ctx.lineTo(chart.valToPos(points[1][0], 'x', true), chart.valToPos(points[1][1] / divisor, 'y', true));
					ctx.stroke();
					ctx.restore();
				}],
				setScale: [function (chart, key) {
					if (key !== 'x') {
						return;
					}
					reset.disabled = Math.abs(chart.scales.x.min - fullMin) < 1 && Math.abs(chart.scales.x.max - fullMax) < 1;
					range.textContent = months.format(new Date(chart.scales.x.min * 1000)) + ' - ' + months.format(new Date(chart.scales.x.max * 1000));
				}]
			}
		}, data, host);
		figure.querySelector('[data-stuh-fmp-static]').hidden = true;
		reset.addEventListener('click', function () {
			plot.setScale('x', { min: fullMin, max: fullMax });
		});
		var resize = new ResizeObserver(function () {
			if (host.clientWidth > 0 && host.clientWidth !== plot.width) {
				plot.setSize({ width: host.clientWidth, height: 420 });
			}
		});
		resize.observe(host);
		window.addEventListener('pagehide', function (event) {
			if (!event.persisted) {
				resize.disconnect();
				plot.destroy();
			}
		}, { once: true });
	});
}());
