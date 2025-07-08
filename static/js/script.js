document.addEventListener('DOMContentLoaded', function() {
    console.log('Скрипт загружен, инициализация WebSocket');
    const socket = io({ transports: ['websocket'] });

    socket.on('connect', function() {
        console.log('Успешно подключено к WebSocket');
        const conversationId = window.location.pathname.split('/').pop();
        if (conversationId) {
            console.log('Присоединение к комнате:', conversationId);
            socket.emit('join', { conversation_id: conversationId });
        } else {
            console.error('Ошибка: conversationId не найден в URL');
        }
    });

    socket.on('connect_error', function(error) {
        console.error('Ошибка подключения к WebSocket:', error);
    });

    socket.on('new_message', function(data) {
        console.log('Получено новое сообщение:', data);
        const messages = document.getElementById('messages');
        if (!messages) {
            console.error('Элемент #messages не найден в DOM');
            return;
        }
        const messageDiv = document.createElement('div');
        const isSent = data.sender_id === window.currentUserId;
        messageDiv.className = 'message ' + (isSent ? 'sent' : 'received');
        messageDiv.setAttribute('data-message-id', data.message_id || 'new-' + Date.now());
        messageDiv.innerHTML = `<strong>${data.sender}</strong>: ${data.message} <br><small>${new Date(data.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})} <span class="status">✓✓</span></small>`;
        messages.appendChild(messageDiv);
        messages.scrollTop = messages.scrollHeight;
        console.log('Сообщение добавлено в DOM:', messageDiv.outerHTML);

        if (!isSent && document.hidden) {
            console.log('Отправка уведомления для:', data.sender);
            if (Notification.permission === 'granted') {
                new Notification('Новое сообщение от ' + data.sender, {
                    body: data.message,
                    icon: '/static/avatars/default.png'
                });
            } else if (Notification.permission !== 'denied') {
                Notification.requestPermission().then(permission => {
                    if (permission === 'granted') {
                        new Notification('Новое сообщение от ' + data.sender, {
                            body: data.message,
                            icon: '/static/avatars/default.png'
                        });
                    }
                });
            }
        }
    });

    const chatForm = document.getElementById('chat-form');
    if (chatForm) {
        console.log('Форма #chat-form найдена, установка обработчика');
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault(); // Prevent default form submission
            console.log('Обработчик submit вызван');
            const messageInput = document.getElementById('message-input');
            const message = messageInput.value.trim();
            const conversationId = window.location.pathname.split('/').pop();
            if (message && conversationId) {
                console.log('Отправка сообщения:', { conversation_id: conversationId, message: message });
                socket.emit('send_message', {
                    conversation_id: conversationId,
                    message: message
                });
                messageInput.value = '';
                console.log('Поле ввода очищено');
            } else {
                console.error('Ошибка: сообщение или conversationId пусты', { message, conversationId });
            }
        });
    } else {
        console.error('Элемент #chat-form не найден в DOM');
    }

    if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
        console.log('Запрос разрешения на уведомления');
        Notification.requestPermission();
    }
});