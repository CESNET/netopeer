(function ($) {
	$.fn.extend({
		gips: function (options) {
			var settings = $.extend({ bottom: '30px', delay: 500, autoHide: false, pause: 5000, animationSpeed: 500, placement: 'top', theme: 'purple', imagePath: 'images/close.png', text: 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et.' }, options);
			return this.each(function () {
				var control = $(this);
				var iconDirection = 'top';
				if (settings.placement == 'top')
					iconDirection = 'bottom';
				if (settings.placement == 'bottom')
					iconDirection = 'top';
				if (settings.placement == 'left')
					iconDirection = 'right';
				if (settings.placement == 'right')
					iconDirection = 'left';

				var closebtn = '';
				if (!settings.autoHide)
					closebtn = '<img src="' + settings.imagePath + '" class="gips-close" alt="close" />';
				var toolTipContainer = $('<div class="gips-container"><div class="gips-body ' + settings.theme + '">' + settings.text + '' +
					'</div><div class="gips-icon gips-icon-' + iconDirection + ' ' + settings.theme + '"></div></div>');

				control.before(toolTipContainer);
				var delay = settings.delay;
				var toolTip = toolTipContainer;
				toolTipHeight = toolTip.outerHeight();
				toolTip.css({display:'none'}).find('div').css({ display: 'none', opacity: 0 });
				var toolTipBody = $('.gips-body', toolTipContainer);
				var toolTipIcon = $('.gips-icon', toolTipContainer);
				var placement = settings.placement;
				var interval;
				control.mouseover(function () {
					var left = $(this).position().left - parseInt(toolTipIcon.css('margin-left'), 10);
					var bottom = settings.bottom;

					toolTipIcon.css('bottom', 0 - toolTipIcon.outerHeight());
					toolTip.css({ left: left, bottom: bottom });
					interval = setTimeout(function () {
						showToolTip(toolTip);
					}, delay);
				}).mouseout(function () {
					if (!settings.autoHide) {
						clearTimeout(interval);
						hideToolTip(toolTip);
					}
				}).keydown(function () {
					clearTimeout(interval);
					hideToolTip(toolTip);
				});

				function showToolTip(toolTip) {
					//toolTip.fadeIn('slow');
					toolTip.css({ display: '' }).find('div').css('display', '').stop(false, true).animate({ opacity: 1 }, settings.animationSpeed, function () {
						if (settings.autoHide) {
							setTimeout(function () {
								hideToolTip(toolTip);
							}, settings.pause);
						}
					});
				}
				function hideToolTip(toolTip) {
					//                    toolTip.fadeOut('slow');
					toolTip.css({ display: 'none' }).find('div').stop(false, true).animate({ opacity: 0 }, settings.animationSpeed, function () {
						$(this).css('display', 'none');
					});
				}

			});
		}
	});
})(jQuery);
