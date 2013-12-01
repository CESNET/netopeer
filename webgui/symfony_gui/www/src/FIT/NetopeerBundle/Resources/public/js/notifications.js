var notifOutput;
var notificationsHeight = 0.1; // in percent
var notifications = new Array();

function notifInit() {
	notifOutput = $("#block--notifications");

	notifOutput.on('click', '#js-get-notif-history', function(e) {
		e.preventDefault();

		processNotifFromHistory($(this).data().key, $(this).attr('href'));
	});
}

function notifResizable() {
	if (!notifOutput) {
		notifInit();
	}

	if (!$('.ui-resizable-handle').length) {
		try {
			if ($(notifOutput).resizable) {
				$(notifOutput).resizable('destroy');
			}
		} catch(err) {
			// nothing happened, resizable not initialized yet
		}
		$(notifOutput).resizable({
			handles: 'n',
			minHeight: 10,
			resize: function(event, ui) {
				ui.size.width = ui.originalSize.width;
				ui.position.left = ui.originalPosition.left;
				notificationsHeight = ui.size.height * 100 / $(window).height();
				ui.position.top = $(window).height() * (1 - notificationsHeight);
			}
		});
	}
}

function getNotifWebSocket(key, hash, wsUri) {
	notifResizable();

	var socket;
	if (notifications[key] === undefined) {
		socket = new $.fn.notifWebSocket(key, wsUri);
		var sendInterval = setInterval(function() {
			if (socket.isActive === true) {
				socket.doSend(hash + ' -10 0');
				clearInterval(sendInterval);
			}
		}, 1000);
	} else {
		socket = notifications[key];
		if (!notifOutput.find('.notif').length) {
			socket.printSavedMessages();
		}
	}

	return socket;
}

function processNotifFromHistory(key, href) {
	$.ajax({
		url: href,
		dataType: "json",
		success: function(data, textStatus, jqXHR) {
			if (data['type'] === 2) {
				if (data.errors.length) {
					$.each(data.errors, function(i,e) {
						notifications[key].addError(e, true);
					});
				}
			} else if (data['snippets'] !== undefined) {
				$.nette.success(data);
			} else {
				$.each(data.notifications, function(i, el) {
					notifications[key].addMessage(el, true);
				});
			}
		},
		error: function() {
			notifications[key].addError("Could not load notifications history.")
		}
	});
}

function unsetNotificationsForKey(key) {
	notifications.splice(notifications.indexOf(key),1);
}

function openipdialog() {
	$.ajax({
		url: $(this).attr('href'),
		success: function(data, textStatus, jqXHR) {
			$('#ipModalCover').html(data)
												.modal({show:true})
												.on('hidden.bs.modal', function () {
				$("#ipModalCover").html('');
			})
		}
	});
	return false;
}

$.fn.notifWebSocket = function(key, wsUri) {
	this.key = key;
	this.messages = new Array();
	if (notifications[key] === undefined) {
		notifications[key] = new Array();
	}
	if (!notifications[key].length) {
		this.websocket = new WebSocket(wsUri, "notification-protocol");
		notifications[key] = this;

		this.websocket.onopen = function(evt) {
			notifications[key].isActive = true;
			notifications[key].addInfo("Connection establised.");
		};

		this.websocket.onclose = function(evt) {
			notifications[key].isActive = false;
			notifications[key].addInfo("Connection closed.");
		};

		this.websocket.onmessage = function(evt) {
			// TODO: rozparsovat zpravu (element: hodnota)
			notifications[key].addMessage(evt.data);
		};
		this.websocket.onerror = function(evt) {
			notifications[key].addError(evt.data);
		};

		this.doSend = function(message) {
			this.websocket.send(message);
			this.addSend(message);
		};

		this.addInfo = function(mess, fromHistory) {
			this.writeToScreen(mess, "info", "Info:", fromHistory);
		};

		this.addError = function(mess, fromHistory) {
			this.writeToScreen(mess, "error red", "Error:", fromHistory);
		};

		this.addMessage = function(mess, fromHistory) {
			this.writeToScreen(mess, "message green", "Message:", fromHistory);
		};

		this.addSend = function(mess, fromHistory) {
			this.writeToScreen(mess, "send", "Sent:", fromHistory);
		};

		this.saveMessage = function(mess) {
			this.messages.push(mess);
		};

		this.printSavedMessages = function() {
			var i = 0;
			var notifCover = notifOutput.find('.notif-cover');
			while(i < this.messages.length) {
				notifCover.append(this.messages[i]);
				i++;
			}
		};

		this.writeToScreen = function(mess, textClass, text, fromHistory) {
			if (!notifOutput) {
				notifInit();
			}

			var parsed = mess;
			var parsed_text = mess;
			var parsed_time = '';
			if (mess[0] === '{') {
				/* TODO sanitize string? handle error? */
				parsed = $.parseJSON(mess);
			}
			if (typeof parsed == 'object') {
				parsed_text = parsed.content;
				parsed_time = parsed.eventtime;
			}

			var output;
			try {
				var xml = $($.parseXML(parsed_text));
				if (xml) {
					output = $("<div></div>").append($("<span></span>").addClass('root-tag').text(xml.contents().prop('tagName').toLocaleUpperCase()));
					xml.contents().children().each(function(i, e) {
						var messtext;
						if ($(e).prop('tagName') == "source-host") {
							messtext = $("<a/>").attr({
								'href': lookupIpUrl.replace("REPLACE_IP", $(e).text()),
								'class': 'tagValue ipHref'
							}).text($(e).text());
						} else {
							messtext = $(e).text();
						}
						output.append($("<span></span>").addClass('tagName').text($(e).prop('tagName') + ": "));
						var value = $("<span></span>").addClass('tagValue');
						value.html(messtext);
						$(value).find('.ipHref').click(openipdialog);
						output.append(value);
					});
					parsed_text = output;
				}
			} catch (err) {
				// we don't care - mess is not probably valid XML string
			}

			output = $("<div></div>").addClass('notif').append($("<strong></strong>").addClass(textClass).text(text)).append($('<span></span>').addClass('mess').html(parsed_text));
			if (parsed_time !== '') {
				if (!isNaN(parsed_time)) {
					var time = new Date();
					time.setTime(parsed_time * 1000);
					parsed_time = "";
					parsed_time += time.toUTCString();
				}
				output.prepend($("<div></div>").addClass('time').text(parsed_time));
			}
			var notifCover;
			if (fromHistory === true) {
				notifCover = notifOutput.find('.notif-history-cover');
			} else {
				notifCover = notifOutput.find('.notif-cover');
				this.saveMessage(output);
			}

			notifCover.append(output);
			notifCover.animate({
				scrollTop: notifCover.scrollTop() + $(output).offset().top
			}, 10);
			notifCover.animate({
				opacity: 0.3
			}, 200, function() {
				notifCover.animate({
					opacity: 1
				}, 100);
			});

		};
	}

	return this;
};

