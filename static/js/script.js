document.addEventListener('DOMContentLoaded', function() {
    console.log('Скрипт загружен, инициализация WebSocket');
    const socket = io({ transports: ['websocket'] });

    socket.on('connect', function() {
        console.log('Успешно подключено к WebSocket');
        const conversationId = window.location.pathname.split('/').pop();
        if (conversationId && !isNaN(conversationId)) {
            console.log('Присоединение к комнате:', conversationId);
            socket.emit('join', { conversation_id: conversationId });
        } else {
            console.log('Не найден ID беседы в URL, пропускаем присоединение к комнате');
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
        // Get current user ID from a data attribute or global variable
        const currentUserId = document.body.getAttribute('data-user-id') || window.currentUserId;
        const isSent = data.sender_id == currentUserId;
        messageDiv.className = 'message ' + (isSent ? 'sent' : 'received');
        messageDiv.setAttribute('data-message-id', data.message_id || 'new-' + Date.now());
        
        const messageTime = new Date(data.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        messageDiv.innerHTML = `<strong>${data.sender}</strong>: ${data.message} <br><small>${messageTime} <span class="status">✓✓</span></small>`;
        
        messages.appendChild(messageDiv);
        messages.scrollTop = messages.scrollHeight;
        console.log('Сообщение добавлено в DOM:', messageDiv.outerHTML);

        if (!isSent && document.hidden) {
            console.log('Отправка уведомления для:', data.sender);
            if (Notification.permission === 'granted') {
                new Notification('Новое сообщение от ' + data.sender, {
                    body: data.message,
                    icon: '/static/orig.jpg'
                });
            } else if (Notification.permission !== 'denied') {
                Notification.requestPermission().then(permission => {
                    if (permission === 'granted') {
                        new Notification('Новое сообщение от ' + data.sender, {
                            body: data.message,
                            icon: '/static/orig.jpg'
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
            console.log('Обработчик submit вызван, форма отправки предотвращена');
            const messageInput = document.getElementById('message-input');
            if (!messageInput) {
                console.error('Поле ввода #message-input не найдено');
                return false;
            }
            const message = messageInput.value.trim();
            const conversationId = window.location.pathname.split('/').pop();
            if (message && conversationId && !isNaN(conversationId)) {
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
            return false; // Additional safety to prevent form submission
        });

        // Add Enter key handler for message input
        const messageInput = document.getElementById('message-input');
        if (messageInput) {
            messageInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    chatForm.dispatchEvent(new Event('submit'));
                }
            });
        }
    } else {
        console.log('Элемент #chat-form не найден в DOM - это нормально для страниц без чата');
    }

    if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
        console.log('Запрос разрешения на уведомления');
        Notification.requestPermission();
    }
});