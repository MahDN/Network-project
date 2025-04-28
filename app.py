
import os
import secrets
import datetime
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, abort, make_response, g) # session مستقیما برای user_id استفاده نمی‌شود
from flask_sqlalchemy import SQLAlchemy
# (دستی شد)
# from flask_login import (LoginManager, UserMixin, login_user, logout_user,
#                          login_required, current_user) 
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse, urljoin

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secure-dev-secret-key-manual') # کلید مخفی حیاتی است
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2) # زمان انقضای نشست

# --- Database Configuration ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions ---
db = SQLAlchemy(app)
# --- LoginManager (دستی شد)---
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'
# login_manager.login_message = "برای دسترسی به این صفحه، لطفا ابتدا وارد شوید."
# login_manager.login_message_category = "info"

# --- Cache Control Header ---
@app.after_request
def set_response_headers(response):
    if response.status_code == 200 and response.mimetype == 'text/html':
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# --- Database Models ---

# UserMixin (دستی)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user') # 'user' or 'admin'
    posts = db.relationship('Post', backref='author', lazy=True, cascade="all, delete-orphan")
    # رابطه با نشست‌های سرور (اختیاری ولی مفید)
    server_sessions = db.relationship('ServerSession', backref='user', lazy='dynamic', cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # تابع check_password_hash مستقیما استفاده می‌شود
        return check_password_hash(self.password_hash, password)

    # is_authenticated, is_active, is_anonymous, get_id (دستی شدند)(مربوط به UserMixin)

    def __repr__(self):
        return f'<User {self.username} (Role: {self.role})>'

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Post {self.id} by User {self.user_id}>'

# *** مدل جدید برای نشست‌های سمت سرور ***
class ServerSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_agent = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))

    def __repr__(self):
        return f'<ServerSession {self.session_id} for User {self.user_id}>'


# --- Flask-Login User Loader (دستی شد)---
# @login_manager.user_loader
# def load_user(user_id):
#     return db.session.get(User, int(user_id))

# --- Manual User Loading from Server Session Cookie ---
@app.before_request
def load_user_from_server_session():
    session_id = request.cookies.get('server_session_id')
    g.user = None # پیش فرض: کاربر لاگین نیست
    g.current_session = None # نشست فعلی را نگه می‌داریم (برای لاگ‌اوت)

    if not session_id:
        return # کوکی وجود ندارد

    server_session = ServerSession.query.filter_by(session_id=session_id).first()

    if server_session:
        now = datetime.now(timezone.utc)
        session_lifetime = app.config['PERMANENT_SESSION_LIFETIME']

        # انقضا بر اساس آخرین مشاهده
        if now > server_session.last_seen + session_lifetime:
            print(f"Server session {session_id} expired based on last_seen.")
            try:
                db.session.delete(server_session)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error deleting expired session {session_id}: {e}")
            return

        # اگر نشست معتبر است، کاربر را پیدا و در g ذخیره میشود
        user = db.session.get(User, server_session.user_id) # استفاده از db.session.get
        if user:
            g.user = user
            g.current_session = server_session
            # به‌روزرسانی زمان آخرین مشاهده نشست
            try:
                server_session.last_seen = now
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.warning(f"Could not update last_seen for session {session_id}: {e}")
        else:
            # اگر کاربر مرتبط با نشست پیدا نشد، نشست را پاک کن
            print(f"User ID {server_session.user_id} not found for session {session_id}. Deleting session.")
            try:
                db.session.delete(server_session)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error deleting session for non-existent user {server_session.user_id}: {e}")


# --- Helper Functions ---

# *** دکوراتور دستی به جای @login_required از flask-login ***
def login_required_server_session(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # g.user توسط load_user_from_server_session تنظیم شده است
        if getattr(g, 'user', None) is None:
            flash("برای دسترسی به این صفحه، لطفا ابتدا وارد شوید.", "info")
            # ارسال کاربر به صفحه لاگین و ذخیره صفحه فعلی برای بازگشت
            return redirect(url_for('login', next=request.url))
        # اگر کاربر لاگین بود، تابع اصلی را اجرا کن
        return f(*args, **kwargs)
    return decorated_function

# *** دکوراتور admin_required با استفاده از g.user ***
def admin_required(func):
    """Decorator برای محدود کردن دسترسی به ادمین‌ها با استفاده از g.user"""
    @wraps(func)
    def decorated_view(*args, **kwargs):
        # بررسی اینکه آیا کاربر در g وجود دارد و نقش او 'admin' است
        current_user = getattr(g, 'user', None)
        if current_user is None or current_user.role != 'admin':
            abort(403, description="شما دسترسی ادمین برای مشاهده این صفحه را ندارید.")
        return func(*args, **kwargs)
    return decorated_view

def is_safe_url(target):
    """جلوگیری از حملات Open Redirect"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# --- Routes ---

@app.route('/')
@login_required_server_session # استفاده از دکوراتور دستی
def index():
    """صفحه اصلی - نمایش پست‌ها و قابلیت جستجو"""
    search_query = request.args.get('q', '').strip()
    query = Post.query.order_by(Post.timestamp.desc())

    if search_query:
        query = query.filter(Post.text.ilike(f'%{search_query}%'))
        posts_to_show = query.all()
    else:
        # نمایش 30 پست اخیر (مگر اینکه ادمین باشد)
        posts_to_show = query.limit(30).all()

    # اگر کاربر ادمین باشد، همه پست‌ها را می‌بیند (حتی بدون جستجو)
    # g.user باید اینجا در دسترس باشد چون login_required_server_session اجرا شده
    if g.user and g.user.role == 'admin' and not search_query:
         posts_to_show = query.all() # ادمین همه پست‌ها را می‌بیند اگر جستجو نکرده باشد

    # **نکته:** تمپلیت index.html باید از g.user استفاده کند
    return render_template('index.html', posts=posts_to_show, search_query=search_query)

@app.route('/my-posts')
@login_required_server_session # استفاده از دکوراتور دستی
def my_posts():
    """نمایش صفحه‌ای فقط با پست‌های کاربر لاگین شده"""
    user_posts = Post.query.filter_by(user_id=g.user.id).order_by(Post.timestamp.desc()).all()
    # **نکته:** تمپلیت my_posts.html باید از g.user استفاده کند
    return render_template('my_posts.html', posts=user_posts)


@app.route('/admin')
@login_required_server_session # اول چک لاگین
@admin_required             # بعد چک ادمین
def admin_dashboard():
    """داشبورد ادمین - نمایش کاربران و فرم افزودن کاربر"""
    all_users = User.query.order_by(User.role, User.username).all()
    # **نکته:** تمپلیت admin.html باید از g.user استفاده کند
    return render_template('admin.html', users=all_users)

@app.route('/admin/create_user', methods=['POST'])
@login_required_server_session
@admin_required
def admin_create_user():
    """پردازش فرم ایجاد کاربر جدید از پنل ادمین"""
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    if not username or not password or not role:
        flash('تمام فیلدها (نام کاربری، رمز عبور، نقش) الزامی هستند.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if role not in ['user', 'admin']:
        flash('نقش انتخاب شده نامعتبر است (فقط user یا admin مجاز است).', 'warning')
        return redirect(url_for('admin_dashboard'))

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash(f"نام کاربری '{username}' از قبل وجود دارد.", 'warning')
        return redirect(url_for('admin_dashboard'))

    new_user = User(username=username, role=role)
    new_user.set_password(password) # هش کردن رمز

    try:
        db.session.add(new_user)
        db.session.commit()
        flash(f"کاربر '{username}' با نقش '{role}' با موفقیت ایجاد شد.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطا در ایجاد کاربر: {e}', 'danger')
        # از g.user برای لاگ استفاده می‌کنیم
        app.logger.error(f"Admin '{g.user.username}' failed to create user '{username}': {e}")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/set_role', methods=['POST'])
@login_required_server_session
@admin_required
def admin_set_user_role(user_id):
    """تغییر نقش کاربر توسط ادمین"""
    admin_password = request.form.get('admin_password')
    new_role = request.form.get('new_role')

    # 1. بررسی رمز عبور ادمین فعلی (با استفاده از g.user)
    if not g.user.check_password(admin_password):
        flash('رمز عبور ادمین نادرست است.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # 2. بررسی نقش جدید
    if new_role not in ['user', 'admin']:
        flash('نقش انتخاب شده نامعتبر است.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # 3. یافتن کاربری که قرار است ویرایش شود
    user_to_modify = db.session.get(User, user_id)
    if not user_to_modify:
        flash('کاربر مورد نظر یافت نشد.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # 4. جلوگیری از تغییر نقش خود ادمین
    if user_to_modify.id == g.user.id:
        flash('شما نمی‌توانید نقش خود را تغییر دهید.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # 5. انجام تغییر نقش
    try:
        user_to_modify.role = new_role
        db.session.commit()
        flash(f"نقش کاربر '{user_to_modify.username}' با موفقیت به '{new_role}' تغییر یافت.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطا در تغییر نقش کاربر: {e}', 'danger')
        app.logger.error(f"Admin '{g.user.username}' failed to set role for user ID {user_id}: {e}")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required_server_session
@admin_required
def admin_delete_user(user_id):
    """حذف کاربر توسط ادمین"""
    admin_password = request.form.get('admin_password')

    # 1. بررسی رمز عبور ادمین فعلی (با g.user)
    if not g.user.check_password(admin_password):
        flash('رمز عبور ادمین نادرست است.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # 2. یافتن کاربری که قرار است حذف شود
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('کاربر مورد نظر یافت نشد.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # 3. جلوگیری از حذف خود ادمین
    if user_to_delete.id == g.user.id:
        flash('شما نمی‌توانید حساب کاربری خود را حذف کنید.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # 4. انجام حذف کاربر (نشست‌ها و پست‌هایش هم به خاطر cascade حذف می‌شوند)
    try:
        username_deleted = user_to_delete.username # نام را قبل از حذف نگه داریم
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f"کاربر '{username_deleted}' با موفقیت حذف شد.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطا در حذف کاربر: {e}', 'danger')
        app.logger.error(f"Admin '{g.user.username}' failed to delete user ID {user_id}: {e}")

    return redirect(url_for('admin_dashboard'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required_server_session # استفاده از دکوراتور دستی
def profile():
    """نمایش پروفایل و فرم تغییر رمز عبور"""
    # g.user در اینجا قطعا وجود دارد به خاطر دکوراتور
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # 1. بررسی رمز عبور فعلی (با g.user)
        if not g.user.check_password(current_password):
            flash('رمز عبور فعلی نادرست است.', 'danger')
        elif not new_password:
             flash('رمز عبور جدید نمی‌تواند خالی باشد.', 'warning')
        elif new_password != confirm_new_password:
            flash('رمز عبور جدید و تکرار آن با هم مطابقت ندارند.', 'warning')
        else:
            try:
                # *** مهم: قبل از تغییر رمز، تمام نشست‌های دیگر این کاربر را حذف کنید ***
                # این کار باعث می‌شود کاربر از دستگاه‌های دیگر خارج شود
                sessions_to_delete = ServerSession.query.filter_by(user_id=g.user.id).all()
                current_session_id = getattr(g, 'current_session', None).session_id if getattr(g, 'current_session', None) else None
                for sess in sessions_to_delete:
                    # نشست فعلی را حذف نکنید تا کاربر لاگ‌اوت نشود
                    if sess.session_id != current_session_id:
                        db.session.delete(sess)

                # حالا رمز عبور را تغییر دهید
                g.user.set_password(new_password) # هش کردن و تنظیم رمز جدید
                db.session.commit() # ذخیره رمز جدید و حذف نشست‌های قدیمی
                flash('رمز عبور شما با موفقیت تغییر کرد و از دستگاه‌های دیگر خارج شدید.', 'success')

            except Exception as e:
                db.session.rollback()
                flash(f'خطایی هنگام تغییر رمز عبور رخ داد: {e}', 'danger')
                app.logger.error(f"Error changing password for user '{g.user.username}': {e}")

        # نمایش دوباره فرم (چه موفقیت‌آمیز بود چه خطا داد)
        # **نکته:** تمپلیت profile.html باید از g.user استفاده کند
        return render_template('profile.html')

    # درخواست GET: فقط نمایش فرم
    # **نکته:** تمپلیت profile.html باید از g.user استفاده کند
    return render_template('profile.html')


@app.route('/profile/delete', methods=['POST'])
@login_required_server_session # استفاده از دکوراتور دستی
def delete_profile():
    """حذف حساب کاربری توسط خود کاربر"""
    password = request.form.get('password')

    # 1. بررسی رمز عبور کاربر فعلی (با g.user)
    if not g.user.check_password(password):
        flash('رمز عبور وارد شده برای تایید حذف نادرست است.', 'danger')
        return redirect(url_for('profile'))

    # 2. جلوگیری از حذف ادمین اصلی (ID=1)
    if g.user.id == 1:
         flash('ادمین اصلی (ID=1) اجازه حذف حساب خود را ندارد.', 'warning')
         return redirect(url_for('profile'))

    # 3. انجام عملیات حذف
    try:
        user_to_delete = g.user # کاربر فعلی را می‌گیریم
        username_deleted = user_to_delete.username
        session_to_delete = g.current_session # نشست فعلی را هم حذف می‌کنیم

        # حذف کاربر (نشست‌ها و پست‌ها cascade می‌شوند)
        db.session.delete(user_to_delete)
        # اگر cascade برای نشست‌ها فعال نباشد، دستی حذف کنید:
        # if session_to_delete:
        #    db.session.delete(session_to_delete)
        db.session.commit()

        flash(f'حساب کاربری "{username_deleted}" با موفقیت برای همیشه حذف شد.', 'success')

        # کاربر باید لاگ‌اوت شود چون دیگر وجود ندارد
        response = make_response(redirect(url_for('login')))
        response.set_cookie('server_session_id', '', expires=0, httponly=True) # پاک کردن کوکی
        g.user = None # پاک کردن از g
        g.current_session = None
        return response

    except Exception as e:
        db.session.rollback()
        flash(f'خطایی هنگام حذف حساب رخ داد: {e}', 'danger')
        app.logger.error(f"Error deleting profile for user ID {g.user.id}: {e}")
        # چون خطا داده، کاربر هنوز در g ممکن است باشد، به پروفایل برگردانیم
        return redirect(url_for('profile'))


# *** تابع لاگین با ایجاد نشست سمت سرور ***
@app.route('/login', methods=['GET', 'POST'])
def login():
    """صفحه ورود کاربر (دستی با نشست سمت سرور)"""
    # اگر کاربر از قبل لاگین است (از before_request)
    if getattr(g, 'user', None):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        # استفاده مستقیم از تابع check_password کاربر
        if user and user.check_password(password):
            # کاربر معتبر است -> ایجاد نشست سمت سرور
            session_id = secrets.token_urlsafe(32)
            new_session = ServerSession(
                session_id=session_id,
                user_id=user.id,
                user_agent=request.user_agent.string,
                ip_address=request.remote_addr
            )
            try:
                db.session.add(new_session)
                db.session.commit()

                flash('ورود با موفقیت انجام شد.', 'success')

                # تعیین صفحه بعد از لاگین
                next_page = request.args.get('next')
                if next_page and not is_safe_url(next_page):
                    abort(400) # جلوگیری از Open Redirect

                # اگر ادمین بود به داشبورد برود (مگر اینکه next_page خاصی باشد)
                redirect_target = next_page or (url_for('admin_dashboard') if user.role == 'admin' else url_for('index'))
                response = make_response(redirect(redirect_target))

                # تنظیم کوکی HttpOnly برای نشست
                response.set_cookie(
                    'server_session_id',
                    session_id,
                    max_age=int(app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()),
                    httponly=True,
                    # secure=True, # در HTTPS فعال شود
                    # samesite='Lax'
                )
                return response

            except Exception as e:
                db.session.rollback()
                flash(f'خطا در ایجاد نشست: {e}', 'danger')
                app.logger.error(f"Error creating server session for user '{username}': {e}")
        else:
            flash('نام کاربری یا رمز عبور نامعتبر است.', 'danger')

    # نمایش فرم لاگین در حالت GET یا اگر لاگین ناموفق بود
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """صفحه ثبت نام کاربر جدید (همیشه با نقش 'user')"""
    if getattr(g, 'user', None): # اگر کاربر لاگین است، به ایندکس برود
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('نام کاربری و رمز عبور الزامی است.', 'warning')
            return render_template('register.html'), 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('این نام کاربری قبلا ثبت شده است. لطفا نام دیگری انتخاب کنید.', 'warning')
            return render_template('register.html'), 409 # Conflict

        # کاربران جدید همیشه با نقش 'user' ایجاد می‌شوند
        new_user = User(username=username, role='user')
        new_user.set_password(password) # هش کردن رمز

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('ثبت نام با موفقیت انجام شد. اکنون می‌توانید وارد شوید.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'خطایی هنگام ثبت نام رخ داد: {e}', 'danger')
            app.logger.error(f"Error on registration for '{username}': {e}")

    return render_template('register.html')

# *** تابع لاگ اوت دستی با حذف نشست سرور ***
@app.route('/logout', methods=['POST'])
@login_required_server_session # کاربر باید لاگین باشد تا بتواند لاگ‌اوت کند
def logout():
    """خروج کاربر با حذف نشست از سرور"""
    current_session = getattr(g, 'current_session', None)
    if current_session:
        try:
            # حذف نشست از دیتابیس
            db.session.delete(current_session)
            db.session.commit()
            flash('خروج با موفقیت انجام شد.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'خطا در هنگام خروج: {e}', 'danger')
            app.logger.error(f"Error deleting server session {current_session.session_id} on logout: {e}")
    else:
        # این حالت نباید رخ دهد اگر دکوراتور کار کند
        flash('نشست معتبری برای خروج یافت نشد.', 'warning')

    # پاک کردن کوکی در پاسخ
    response = make_response(redirect(url_for('login')))
    response.set_cookie('server_session_id', '', expires=0, httponly=True)
    # پاک کردن g (اختیاری)
    g.user = None
    g.current_session = None
    return response


@app.route('/posts', methods=['POST'])
@login_required_server_session # استفاده از دکوراتور دستی
def submit_post():
    """ثبت پست جدید"""
    post_text = request.form.get('post_text')
    if not post_text:
        flash('متن پست نمی‌تواند خالی باشد.', 'warning')
        return redirect(url_for('index'))

    # ایجاد پست با استفاده از g.user
    new_post = Post(text=post_text, author=g.user)
    try:
        db.session.add(new_post)
        db.session.commit()
        flash('پست شما با موفقیت ثبت شد.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطایی هنگام ثبت پست رخ داد: {e}', 'danger')
        app.logger.error(f"User '{g.user.username}' failed to submit post: {e}")

    return redirect(url_for('index'))


@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required_server_session # استفاده از دکوراتور دستی
def delete_post(post_id):
    """حذف پست توسط نویسنده آن"""
    post_to_delete = db.session.get(Post, post_id)

    if not post_to_delete:
        abort(404) # پست یافت نشد

    # آیا کاربر لاگین شده (g.user) نویسنده پست است؟
    if post_to_delete.user_id != g.user.id:
        abort(403) # Forbidden

    # انجام حذف
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash('پست شما با موفقیت حذف شد.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطایی هنگام حذف پست رخ داد: {e}', 'danger')
        app.logger.error(f"User '{g.user.username}' failed to delete own post ID {post_id}: {e}")

    # به صفحه‌ای که از آن آمده برگردد یا به ایندکس
    # return redirect(request.referrer or url_for('index'))
    return redirect(url_for('index')) # ساده‌تر


@app.route('/admin/post/<int:post_id>/delete', methods=['POST'])
@login_required_server_session
@admin_required # فقط ادمین
def admin_delete_post(post_id):
    """حذف هر پستی توسط ادمین"""
    # نیازی به چک کردن id=1 نیست، admin_required چک می‌کند نقش ادمین است
    # if g.user.id != 1: # این چک دیگر لازم نیست اگر هر ادمینی بتواند حذف کند
    #     abort(403)

    post_to_delete = db.session.get(Post, post_id)
    if not post_to_delete:
        abort(404)

    # انجام حذف
    try:
        author_username = post_to_delete.author.username # نام نویسنده برای پیام
        db.session.delete(post_to_delete)
        db.session.commit()
        flash(f'پست متعلق به کاربر "{author_username}" با موفقیت توسط ادمین حذف شد.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطایی هنگام حذف پست توسط ادمین رخ داد: {e}', 'danger')
        app.logger.error(f"Admin '{g.user.username}' failed to delete post ID {post_id}: {e}")

    return redirect(url_for('index'))


# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    # **نکته:** تمپلیت 404.html باید از g.user (اگر وجود داشت) استفاده کند
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    # پیام خطا را از description بگیرید اگر وجود داشت
    message = getattr(e, 'description', 'شما اجازه دسترسی به این صفحه یا انجام این عملیات را ندارید.')
    # **نکته:** تمپلیت unauthorized.html باید از g.user (اگر وجود داشت) استفاده کند
    return render_template('unauthorized.html', message=message), 403

# --- Database Initialization ---
def init_db():
    """ایجاد جداول دیتابیس و سوپر ادمین(درصورت عدم وجود)"""
    with app.app_context():
        try:
            db.create_all() # جداول User, Post, ServerSession را ایجاد می‌کند
            print("Database tables checked/created.")
            #ایجاد سوپر ادمین
            if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin', role='admin')
                admin_user.set_password('adminpass') # رمز عبور پیش‌فرض
                db.session.add(admin_user)
                db.session.commit()
                print("Default admin user ('admin'/'adminpass') created.")
        except Exception as e:
            print(f"An error occurred during DB initialization: {e}")
            app.logger.error(f"DB Init error: {e}")


# --- Main Execution ---
if __name__ == '__main__':
    # init_db() # فقط یک بار برای ایجاد اولیه دیتابیس اجرا کنید یا از طریق flask shell
    # ایجاد جداول اگر وجود ندارند در هر اجرا (برای توسعه مناسب است)
    with app.app_context():
        db.create_all()
        # می‌توانید ایجاد ادمین پیش‌فرض را هم اینجا بگذارید اگر می‌خواهید همیشه چک شود
        if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin', role='admin')
                admin_user.set_password('adminpass')
                db.session.add(admin_user)
                db.session.commit()
                print("Default admin user ('admin'/'adminpass') checked/created.")

    app.run(host='0.0.0.0', port=5000, debug=True)