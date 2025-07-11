from flask import Flask, request, jsonify, render_template, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room, disconnect
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Length
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object('config.Config')
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, manage_session=False, cors_allowed_origins="*")

def timestamp_filter(value):
    return str(int(datetime.now().timestamp()))
app.jinja_env.filters['timestamp'] = timestamp_filter

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(100), nullable=True)
    direct_messages_as_user1 = db.relationship('DirectMessage', foreign_keys='DirectMessage.user1_id', backref='user1')
    direct_messages_as_user2 = db.relationship('DirectMessage', foreign_keys='DirectMessage.user2_id', backref='user2')
    groups = db.relationship('Group', secondary='group_members', backref='members')
    sent_messages = db.relationship('Message', backref='sender')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_conversations(self):
        try:
            # Получаем личные сообщения
            direct = DirectMessage.query.filter(
                (DirectMessage.user1_id == self.id) | (DirectMessage.user2_id == self.id)
            ).all()
            # Получаем группы
            group = self.groups
            # Объединяем беседы
            conversations = direct + list(group)
            # Подготавливаем список кортежей (conversation, last_message)
            result = []
            for conv in conversations:
                last_message = conv.messages.order_by(Message.timestamp.desc()).first()
                result.append((conv, last_message))
            # Сортируем по времени последнего сообщения
            result.sort(key=lambda x: x[1].timestamp if x[1] else datetime.min, reverse=True)
            logger.debug(f"Пользователь {self.username} получил {len(result)} бесед")
            return result
        except Exception as e:
            logger.error(f"Ошибка в get_conversations для пользователя {self.username}: {str(e)}")
            return []  # Возвращаем пустой список в случае ошибки

class Conversation(db.Model):
    __tablename__ = 'conversations'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10))
    last_message_timestamp = db.Column(db.DateTime)
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'conversation'
    }
    messages = db.relationship('Message', backref='conversation', lazy='dynamic')

class DirectMessage(Conversation):
    __tablename__ = 'direct_messages'
    id = db.Column(db.Integer, db.ForeignKey('conversations.id'), primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    __mapper_args__ = {
        'polymorphic_identity': 'direct'
    }

class Group(Conversation):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, db.ForeignKey('conversations.id'), primary_key=True)
    name = db.Column(db.String(100))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    __mapper_args__ = {
        'polymorphic_identity': 'group'
    }
    creator = db.relationship('User', backref='created_groups')

group_members = db.Table('group_members',
    db.Column('group_id', db.Integer, db.ForeignKey('groups.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Войти')

class RegisterForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Зарегистрироваться')

class CreateGroupForm(FlaskForm):
    name = StringField('Название группы', validators=[DataRequired(), Length(min=3, max=100)])
    members = SelectMultipleField('Участники', coerce=str, validators=[DataRequired()])
    submit = SubmitField('Создать')

class SettingsForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=3, max=80)])
    avatar = FileField('Аватарка', validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Только изображения!')])
    submit = SubmitField('Сохранить')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chats'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('chats'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.lstrip('@')
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            logger.info(f'Пользователь {username} успешно вошел')
            return redirect(url_for('chats'))
        logger.warning(f'Неуспешная попытка входа для {username}')
        return jsonify({'error': 'Неверные учетные данные'}), 401
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('chats'))
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.lstrip('@')
        password = form.password.data
        if User.query.filter_by(username=username).first():
            logger.warning(f'Попытка регистрации с занятым именем {username}')
            return jsonify({'error': 'Имя пользователя уже занято'}), 400
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user, remember=True)
        logger.info(f'Зарегистрирован новый пользователь {username}')
        return redirect(url_for('chats'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logger.info(f'Пользователь {current_user.username} вышел')
    logout_user()
    return redirect(url_for('login'))

@app.route('/chats')
@login_required
def chats():
    conversations = current_user.get_conversations()
    if conversations is None:
        logger.warning(f"get_conversations вернул None для пользователя {current_user.username}")
        conversations = []
    logger.info(f'Пользователь {current_user.username} открыл список чатов с {len(conversations)} беседами')
    return render_template('chats.html', conversations=conversations)


@app.route('/chat/<int:conversation_id>')
@login_required
def chat(conversation_id):
    conversation = db.session.get(Conversation, conversation_id) or abort(404)
    if isinstance(conversation, DirectMessage):
        if current_user not in [conversation.user1, conversation.user2]:
            logger.warning(f'Пользователь {current_user.username} пытался открыть недоступную беседу {conversation_id}')
            abort(403)
    elif isinstance(conversation, Group):
        if current_user not in conversation.members:
            logger.warning(f'Пользователь {current_user.username} пытался открыть недоступную группу {conversation_id}')
            abort(403)
    messages = conversation.messages.order_by(Message.timestamp.asc()).all()
    logger.info(f'Пользователь {current_user.username} открыл чат {conversation_id} с {len(messages)} сообщениями')
    return render_template('chat.html', conversation=conversation, messages=messages)

@app.route('/start_chat')
@login_required
def start_chat():
    users = User.query.filter(User.id != current_user.id).all()
    logger.info(f'Пользователь {current_user.username} открыл страницу начала чата')
    return render_template('start_chat.html', users=users)

@app.route('/chat_with/<int:user_id>')
@login_required
def chat_with(user_id):
    other = db.session.get(User, user_id) or abort(404)
    min_id = min(current_user.id, other.id)
    max_id = max(current_user.id, other.id)
    direct = DirectMessage.query.filter_by(user1_id=min_id, user2_id=max_id).first()
    if not direct:
        direct = DirectMessage(type='direct', user1_id=min_id, user2_id=max_id)
        db.session.add(direct)
        db.session.commit()
        logger.info(f'Создана новая беседа между {current_user.username} и {other.username}')
    logger.info(f'Пользователь {current_user.username} начал чат с {other.username}')
    return redirect(url_for('chat', conversation_id=direct.id))

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    form = CreateGroupForm()
    if form.validate_on_submit():
        name = form.name.data
        member_ids = form.members.data
        if str(current_user.id) not in member_ids:
            member_ids.append(str(current_user.id))
        group = Group(type='group', name=name, creator_id=current_user.id)
        db.session.add(group)
        db.session.commit()
        for member_id in member_ids:
            user = db.session.get(User, member_id)
            if user:
                group.members.append(user)
        db.session.commit()
        logger.info(f'Пользователь {current_user.username} создал группу {name}')
        return redirect(url_for('chat', conversation_id=group.id))
    users = User.query.filter(User.id != current_user.id).all()
    form.members.choices = [(str(u.id), u.username) for u in users]
    return render_template('create_group.html', form=form)

@app.route('/group/<int:group_id>/add_members', methods=['GET', 'POST'])
@login_required
def add_members(group_id):
    group = db.session.get(Group, group_id) or abort(404)
    if group.creator != current_user:
        logger.warning(f'Пользователь {current_user.username} пытался добавить участников в группу {group_id} без прав')
        abort(403)
    form = CreateGroupForm()
    if form.validate_on_submit():
        member_ids = form.members.data
        for member_id in member_ids:
            user = db.session.get(User, member_id)
            if user and user not in group.members:
                group.members.append(user)
        db.session.commit()
        logger.info(f'Пользователь {current_user.username} добавил участников в группу {group_id}')
        return redirect(url_for('chat', conversation_id=group.id))
    existing = [m.id for m in group.members]
    users = User.query.filter(~User.id.in_(existing)).all()
    form.members.choices = [(str(u.id), u.username) for u in users]
    return render_template('add_members.html', group=group, form=form)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm()
    if form.validate_on_submit():
        new_username = form.username.data.lstrip('@')
        if new_username != current_user.username and User.query.filter_by(username=new_username).first():
            logger.warning(f'Попытка смены имени на занятое {new_username} пользователем {current_user.username}')
            form.username.errors.append('Имя пользователя уже занято')
        else:
            current_user.username = new_username
        if form.avatar.data:
            avatar_file = form.avatar.data
            filename = secure_filename(f"user_{current_user.id}.{avatar_file.filename.rsplit('.', 1)[1].lower()}")
            avatar_path = os.path.join('static/avatars', filename)
            os.makedirs(os.path.dirname(avatar_path), exist_ok=True)
            avatar_file.save(avatar_path)
            current_user.avatar = filename
        db.session.commit()
        logger.info(f'Пользователь {current_user.username} обновил настройки профиля')
        return redirect(url_for('chats'))
    return render_template('settings.html', form=form)

@socketio.on('connect')
def handle_connect(auth=None):
    if current_user.is_authenticated:
        conversations = current_user.get_conversations()
        for conversation, _ in conversations:
            join_room(str(conversation.id))
        logger.info(f'Пользователь {current_user.username} подключился к WebSocket и присоединился к {len(conversations)} комнатам')
    else:
        logger.warning('Неавторизованный пользователь пытался подключиться к WebSocket')
        disconnect()

@socketio.on('join')
def on_join(data):
    if not current_user.is_authenticated:
        logger.warning('Неавторизованный пользователь пытался присоединиться к комнате')
        return
    conversation_id = str(data.get('conversation_id'))
    if not conversation_id:
        logger.error('Ошибка: отсутствует conversation_id в событии join')
        return
    conversation = db.session.get(Conversation, int(conversation_id))
    if not conversation:
        logger.error(f'Ошибка: беседа {conversation_id} не найдена')
        return
    if isinstance(conversation, DirectMessage):
        if current_user not in [conversation.user1, conversation.user2]:
            logger.warning(f'Пользователь {current_user.username} не имеет доступа к беседе {conversation_id}')
            return
    elif isinstance(conversation, Group):
        if current_user not in conversation.members:
            logger.warning(f'Пользователь {current_user.username} не состоит в группе {conversation_id}')
            return
    join_room(conversation_id)
    logger.info(f'Пользователь {current_user.username} присоединился к комнате {conversation_id}')

@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        logger.warning('Неавторизованный пользователь пытался отправить сообщение')
        return
    conversation_id = str(data.get('conversation_id'))
    message_text = data.get('message')
    logger.debug(f'Получено событие send_message: conversation_id={conversation_id}, message={message_text}')
    if not conversation_id or not message_text:
        logger.error(f'Ошибка: отсутствует conversation_id={conversation_id} или message={message_text}')
        return
    conversation = db.session.get(Conversation, int(conversation_id))
    if not conversation:
        logger.error(f'Ошибка: беседа {conversation_id} не найдена')
        return
    if isinstance(conversation, DirectMessage):
        if current_user not in [conversation.user1, conversation.user2]:
            logger.warning(f'Пользователь {current_user.username} не имеет доступа к беседе {conversation_id}')
            return
    elif isinstance(conversation, Group):
        if current_user not in conversation.members:
            logger.warning(f'Пользователь {current_user.username} не состоит в группе {conversation_id}')
            return
    message = Message(conversation_id=conversation.id, sender_id=current_user.id, text=message_text)
    db.session.add(message)
    db.session.commit()
    conversation.last_message_timestamp = message.timestamp
    db.session.commit()
    logger.info(f'Сообщение сохранено в базе: id={message.id}, conversation_id={conversation_id}, sender={current_user.username}, text={message_text}')
    socketio.emit('new_message', {
        'sender': current_user.username,
        'sender_id': current_user.id,
        'message': message_text,
        'timestamp': message.timestamp.isoformat(),
        'conversation_id': conversation_id,
        'message_id': message.id
    }, room=conversation_id)
    logger.info(f'Сообщение отправлено в комнату {conversation_id}: {message_text}')

with app.app_context():
    db.create_all()