import os
import secrets
from flask import (Flask, render_template, request, redirect, url_for, jsonify, flash, abort, make_response, g) # g برای ذخیره اطلاعات کاربر در طول یک درخواست استفاده می‌شود
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse, urljoin

# --- کانفیگ اپ Flask ---
app = Flask(__name__)
# کلید مخفی برای امنیت سشن ها و فرم‌ها
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-secure-secret-key')
# تنظیم زمان پیش‌فرض انقضای سشن (در صورت عدم انتخاب Remember Me)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2) # زمان پیش‌فرض انقضای سشن (مثلا 1 دقیقه برای تست)

# ---  کانفیگ دیتابیس SQLite ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # غیرفعال کردن ردیابی تغییرات SQLAlchemy برای بهینه‌سازی (**پیشنهاد چت**)

# --- مقداردهی اولیه برای مدلها ---
db = SQLAlchemy(app)


# --- کنترل کش مرورگر ---
@app.after_request
def set_response_headers(response):
    """
    افزودن هدرهای کنترل کش به پاسخ‌ها برای جلوگیری از کش شدن صفحات در مرورگر
    این کار باعث می‌شود کاربر همیشه آخرین نسخه صفحات را ببیند، مخصوصا بعد از لاگین/لاگ‌اوت
    """
    if response.status_code == 200 and response.mimetype == 'text/html':
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


# --- مدل های دیتابیس ---
class User(db.Model):
    """مدل برای ذخیره کاربران."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # هش رمز عبور ذخیره می‌شود، نه خود رمز
    role = db.Column(db.String(20), nullable=False, default='user') # نقش کاربر: 'user' یا 'admin'
    
    # ارتباط 1 به many -- با حذف کاربر، پست‌هایش هم حذف می‌شوند 
    posts = db.relationship('Post', backref='author', lazy=True, cascade="all, delete-orphan")
    # ارتباط 1 many با سشن های سرور: با حذف کاربر، سشن هایش هم حذف می‌شوند
    server_sessions = db.relationship('ServerSession', backref='user', lazy='dynamic', cascade="all, delete-orphan")

    def set_password(self, password):
        """هش کردن و تنظیم رمز عبور."""
        self.password_hash = generate_password_hash(password) # توابع موجود

    def check_password(self, password):
        """بررسی صحت رمز عبور وارد شده با هش ذخیره شده."""
        return check_password_hash(self.password_hash, password) # توابع موجود

    def __repr__(self):
        return f'<User {self.username} (Role: {self.role})>'


class Post(db.Model):
    """مدل برای ذخیره پست‌های کاربران."""
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)) # زمان ایجاد پست با منطقه زمانی گرینویچ
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # کلید خارجی به شمای یوزر

    def __repr__(self):
        return f'<Post {self.id} by User {self.user_id}>'


class ServerSession(db.Model):
    """مدل برای ذخیره اطلاعات نشست‌های فعال کاربران در سمت سرور."""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), unique=True, nullable=False, index=True) # سشن آیدی (ذخیره شده در کوکی کاربر)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # کلید خارجی به یوزر مرتبط با نشست
    remembered = db.Column(db.Boolean, default=False, nullable=False) # چک کردن remember me
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)) # زمان ایجاد نشست
    last_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)) # آخرین زمان فعالیت با این نشست
    user_agent = db.Column(db.String(200)) # اطلاعات مرورگر و سیستم‌عامل کاربر
    ip_address = db.Column(db.String(50)) # آدرس IP کاربر در زمان ایجاد نشست

    def __repr__(self):
        return f'<ServerSession {self.session_id} for User {self.user_id} (Remembered: {self.remembered})>' # نمایش اطلاعات نشست


# --- دریافت اطلاعات کاربر قبل از هر درخواست ---
@app.before_request
def load_user_from_server_session():
    """
    قبل از پردازش هر درخواست، این تابع اجرا می‌شود.
    سشن آیدی را از کوکی 'server_session_id' می‌خواند،
    نشست معتبر را در دیتابیس جستجو می‌کند،
    و در صورت یافتن و معتبر بودن نشست، اطلاعات کاربر مربوطه
    و خود نشست را در آبجکت g (مخصوص هر درخواست) قرار می‌دهد (g.user و g.current_session).
    همچنین زمان آخرین مشاهده (last_seen) نشست را به‌روزرسانی می‌کند
    و نشست‌های منقضی شده را بررسی و حذف می‌کند.
    """
    session_id = request.cookies.get('server_session_id')
    g.user = None # مقداردهی اولیه g.user در هر درخواست
    g.current_session = None # مقداردهی اولیه g.current_session در هر درخواست

    if not session_id:
        return # اگر کوکی وجود ندارد، کاربر لاگین نیست

    # جستجوی نشست در دیتابیس
    server_session = ServerSession.query.filter_by(session_id=session_id).first()

    if server_session:
        now = datetime.now(timezone.utc)

        # تعیین طول عمر نشست سرور بر اساس وضعیت Remember Me
        if server_session.remembered:
            # اگر Remember Me فعال بوده، عمر نشست در سرور طولانی‌تر شود (مثلا 1 روز )
            session_lifetime = timedelta(days=1)
            # print(f"Session {session_id} is 'Remembered'. Using 1 day lifetime.") # برای دیباگ
        else:
            # اگر نبود، از عمر پیش‌فرض برنامه که اول کار ست کردیم استفاده می‌شود (مثلا 2 دقیقه)
            session_lifetime = app.config['PERMANENT_SESSION_LIFETIME']
            # print(f"Session {session_id} is not 'Remembered'. Using {session_lifetime} lifetime.") # برای دیباگ

        # اطمینان از اینکه last_seen دارای timezone است برای صحت مقایسه
        try:
            # اگر last_seen از نوع naive datetime باشد، آن را aware می‌کنیم
            if server_session.last_seen.tzinfo is None:
                 last_seen_aware = server_session.last_seen.replace(tzinfo=timezone.utc)
            else:
                 last_seen_aware = server_session.last_seen
        except AttributeError:
             app.logger.error(f"Session {session_id} has invalid last_seen attribute or type: {server_session.last_seen}") # برای دیباگ
             # نشست نامعتبر را حذف می‌کنیم
             try:
                 db.session.delete(server_session)
                 db.session.commit()
             except Exception as e:
                 db.session.rollback()
                 app.logger.error(f"Error deleting session {session_id} with invalid last_seen: {e}") #دیباگ
             return

        # بررسی انقضای نشست بر اساس آخرین فعالیت و طول عمر ست شده
        if now > last_seen_aware + session_lifetime:
            print(f"Server session {session_id} expired based on last_seen ({last_seen_aware}) and its lifetime ({session_lifetime}). Deleting.") #دیباگ
            try:
                db.session.delete(server_session)
                db.session.commit()
                # در درخواست بعدی کوکی نامعتبر خواهد بود
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error deleting expired session {session_id}: {e}")
            return # نشست منقضی شده است، کاربر لاگین نیست

        # اگر نشست معتبر است، کاربر مربوطه را پیدا می‌کنیم
        user = db.session.get(User, server_session.user_id)
        if user:
            # کاربر و نشست فعلی را در g ذخیره می‌کنیم
            g.user = user
            g.current_session = server_session
            try:
                # زمان آخرین مشاهده را به‌روز می‌کنیم
                server_session.last_seen = now
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.warning(f"Could not update last_seen for session {session_id}: {e}") # لاگ برای دیباگ 
        else:
            # اگر کاربری با آن user_id وجود نداشت (مثلا کاربر حذف شده)، نشست را حذف می‌کنیم
            print(f"User ID {server_session.user_id} not found for session {session_id}. Deleting session.")
            try:
                db.session.delete(server_session)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error deleting session for non-existent user {server_session.user_id}: {e}")
            # در انتها اگر کاربری پیدا نشود آبجکت g با مقداردهی اولیه باقی مماند



# --- توابع کمکی و دکوراتورها ---
def login_required_server_session(f):
    """
    دکوراتور برای مسیرهایی که نیاز به لاگین کاربر دارند.
    بررسی می‌کند که آیا g.user (توسط load_user_from_server_session) تنظیم شده است یا خیر.
    اگر کاربر لاگین نباشد، او را به صفحه لاگین هدایت می‌کند.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if getattr(g, 'user', None) is None:
            flash("برای دسترسی به این صفحه، لطفا ابتدا وارد شوید.", "info")
            # ذخیره URL فعلی در پارامتر 'next' تا بعد از لاگین به همین صفحه برگردد
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(func):
    """
    دکوراتور برای محدود کردن دسترسی به مسیرها فقط برای کاربران با نقش 'admin'.
    بررسی می‌کند که آیا g.user وجود دارد و نقش آن 'admin' است.
    """
    @wraps(func)
    def decorated_view(*args, **kwargs):
        current_user = getattr(g, 'user', None)
        # کاربر باید لاگین باشد و نقش ادمین داشته باشد
        if current_user is None or current_user.role != 'admin':
            # نمایش خطای 403 (Forbidden) 
            abort(403, description="برای دسترسی به این صفحه باید ادمین باشید.")
        return func(*args, **kwargs)
    return decorated_view

def is_safe_url(target): # **پیشنهاد چت**
    """
    بررسی می‌کند که آیا URL مقصد برای redirect امن است یا خیر.
    این کار برای جلوگیری از حملات Open Redirect مهم است.
    URL امن، URL ی است که در همان دامنه (host) برنامه باشد.
    """
    ref_url = urlparse(request.host_url) # URL برنامه فعلی
    test_url = urlparse(urljoin(request.host_url, target)) # URL مقصد را کامل و parse می‌کند
    # بررسی می‌کند که پروتکل http یا https باشد و نام دامنه یکی باشد
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc



# --- routes ---
@app.route('/')
@login_required_server_session # این صفحه نیاز به لاگین دارد
def index():
    """
    صفحه اصلی برنامه.
    نمایش پست‌های اخیر یا نتایج جستجو.
    کاربران عادی ۳۰ پست اخیر را می‌بینند (مگر در حال جستجو).
    کاربران ادمین همه پست‌ها را می‌بینند (مگر در حال جستجو).
    """
    search_query = request.args.get('q', '').strip() # دریافت عبارت جستجو از query string
    query = Post.query.order_by(Post.timestamp.desc()) # مرتب‌سازی پست‌ها بر اساس زمان (جدیدترین اول میاد)

    posts_to_show = []
    if search_query:
        # فیلتر کردن پست‌ها بر اساس متن ( بزرگ و کوچکی حروف مهم نیست)
        query = query.filter(Post.text.ilike(f'%{search_query}%'))
        posts_to_show = query.all()
    else:
        # اگر جستجویی انجام نشده باشد
        # کاربر ادمین همه پست‌ها را می‌بیند
        if g.user.role == 'admin':
            posts_to_show = query.all()
        else:
            # کاربر عادی ۳۰ پست اخیر را می‌بیند
            posts_to_show = query.limit(30).all()

    # ارسال لیست پست‌ها و عبارت جستجو به تمپلیت
    return render_template('index.html', posts=posts_to_show, search_query=search_query)

@app.route('/my-posts')
@login_required_server_session # نیاز به لاگین
def my_posts():
    """صفحه نمایش پست‌های کاربر لاگین شده."""
    # فیلتر کردن پست‌ها بر اساس user_id کاربر فعلی (g.user.id)
    user_posts = Post.query.filter_by(user_id=g.user.id).order_by(Post.timestamp.desc()).all()
    return render_template('my_posts.html', posts=user_posts)


@app.route('/admin')
@login_required_server_session # نیاز به لاگین
@admin_required             # نیاز به دسترسی ادمین
def admin_dashboard():
    """داشبورد مدیریتی برای ادمین‌ها."""
    # دریافت لیست تمام کاربران برای نمایش در داشبورد
    all_users = User.query.order_by(User.role, User.username).all() # مرتب‌سازی بر اساس نقش و نام
    return render_template('admin.html', users=all_users)

@app.route('/admin/create_user', methods=['POST'])
@login_required_server_session # نیاز به لاگین
@admin_required             # نیاز به دسترسی ادمین
def admin_create_user():
    """ فرم ایجاد کاربر جدید توسط ادمین."""
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    # بررسی صحت ورودی ها
    if not username or not password or not role: # حداقل یک فیلد خالی باشه
        flash('تمام فیلدها (نام کاربری، رمز عبور، نقش) الزامی هستند.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if role not in ['user', 'admin']: # رول غیر متعارف باشد (مثلا پست مستقیم)
        flash('نقش انتخاب شده نامعتبر است (فقط user یا admin مجاز است).', 'warning')
        return redirect(url_for('admin_dashboard'))

    # بررسی نام کاربری تکراری
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash(f"نام کاربری '{username}' از قبل وجود دارد.", 'warning')
        return redirect(url_for('admin_dashboard'))

    # ساخت  کاربر جدید
    new_user = User(username=username, role=role)
    new_user.set_password(password) # هش کردن رمز عبور

    try:
        db.session.add(new_user)
        db.session.commit()
        flash(f"کاربر '{username}' با نقش '{role}' با موفقیت ایجاد شد.", 'success')
    except Exception as e:
        db.session.rollback() # بازگرداندن تغییرات در صورت وجود خطا
        flash(f'خطا در ایجاد کاربر: {e}', 'danger')
        app.logger.error(f"Admin '{g.user.username}' failed to create user '{username}': {e}")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/set_role', methods=['POST'])
@login_required_server_session # نیاز به لاگین
@admin_required             # نیاز به دسترسی ادمین
def admin_set_user_role(user_id):
    """تغییر نقش یک کاربر توسط ادمین."""
    admin_password = request.form.get('admin_password') # رمز عبور ادمین فعلی برای تایید
    new_role = request.form.get('new_role') # نقش جدید مورد نظر

    #  بررسی رمز عبور ادمین فعلی (g.user)
    if not g.user.check_password(admin_password):
        flash('رمز عبور ادمین نادرست است.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # بررسی صحت نقش جدید
    if new_role not in ['user', 'admin']:
        flash('نقش انتخاب شده نامعتبر است.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # یافتن کاربری که قرار است نقشش تغییر کند
    user_to_modify = db.session.get(User, user_id)
    if not user_to_modify:
        flash('کاربر مورد نظر یافت نشد.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # جلوگیری از تغییر نقش خود ادمین
    if user_to_modify.id == g.user.id:
        flash('شما نمی‌توانید نقش خود را تغییر دهید.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # انجام تغییر نقش و ذخیره در دیتابیس
    try:
        user_to_modify.role = new_role
        db.session.commit()
        flash(f"نقش کاربر '{user_to_modify.username}' با موفقیت به '{new_role}' تغییر یافت.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطا در تغییر نقش کاربر: {e}', 'danger')
        app.logger.error(f"Admin '{g.user.username}' failed to set role for user ID {user_id} to '{new_role}': {e}")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/delete', methods=['DELETE'])
@login_required_server_session
@admin_required
def admin_delete_user(user_id):
    """حذف کاربر توسط ادمین با متد DELETE"""
    # خواندن اطلاعات از بدنه درخواست JSON
    data = request.get_json()
    if not data or 'admin_password' not in data:
        return jsonify({'status': 'error', 'message': 'رمز عبور ادمین برای تایید حذف لازم است.'}), 400

    admin_password_provided = data.get('admin_password')

    #  بررسی رمز عبور ادمین فعلی (g.user)
    if not g.user.check_password(admin_password_provided):
        return jsonify({'status': 'error', 'message': 'رمز عبور ادمین نادرست است.'}), 403 # Forbidden

    # یافتن کاربری که قرار است حذف شود
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        return jsonify({'status': 'error', 'message': 'کاربر مورد نظر یافت نشد.'}), 404

    # جلوگیری از حذف خود ادمین از این طریق
    if user_to_delete.id == g.user.id:
        return jsonify({'status': 'error', 'message': 'شما نمی‌توانید حساب کاربری خود را از این طریق حذف کنید.'}), 403

    # انجام حذف کاربر (نشست‌ها و پست‌هایش هم به خاطر cascade حذف می‌شوند)
    try:
        username_deleted = user_to_delete.username
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': f"کاربر '{username_deleted}' (ID: {user_id}) با موفقیت حذف شد."
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Admin '{g.user.username}' failed to delete user ID {user_id}: {e}")
        return jsonify({'status': 'error', 'message': f'خطا در حذف کاربر: {e}'}), 500


@app.route('/profile', methods=['GET', 'POST'])
@login_required_server_session # نیاز به لاگین
def profile():
    """
    صفحه پروفایل کاربر.
    نمایش فرم تغییر رمز عبور (GET).
    پردازش فرم تغییر رمز عبور (POST).
    """
    if request.method == 'POST':
        # پردازش فرم تغییر رمز
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # بررسی صحت رمز عبور فعلی و رمز جدید
        if not g.user.check_password(current_password):
            flash('رمز عبور فعلی نادرست است.', 'danger')
        elif not new_password:
             flash('رمز عبور جدید نمی‌تواند خالی باشد.', 'warning')
        elif new_password != confirm_new_password:
            flash('رمز عبور جدید و تکرار آن با هم مطابقت ندارند.', 'warning')
        else:
            # اگر مشکلی نبود رمز را تغییر می‌دهیم
            try:
                # حذف تمام نشست‌های دیگر این کاربر 
                current_session_id = g.current_session.session_id if g.current_session else None
                
                # تمام نشست‌های کاربر به جز نشست فعلی را کوئری می‌زنیم
                other_sessions = ServerSession.query.filter(
                    ServerSession.user_id == g.user.id,
                    ServerSession.session_id != current_session_id # نشست فعلی را حذف نکن
                ).all()

                for sess in other_sessions:
                    db.session.delete(sess)

                # تنظیم رمز عبور جدید (هش شده)
                g.user.set_password(new_password)
                # ذخیره تغییرات (رمز جدید و حذف نشست‌های قدیمی)
                db.session.commit()
                flash('رمز عبور شما با موفقیت تغییر کرد و از دستگاه‌های دیگر خارج شدید.', 'success')
                return redirect(url_for('profile'))

            except Exception as e:
                db.session.rollback()
                flash(f'خطایی هنگام تغییر رمز عبور رخ داد: {e}', 'danger')
                app.logger.error(f"Error changing password for user '{g.user.username}': {e}")
        # اگر خطایی در اعتبار سنجی بود، پروفایل دوباره با پیام خطا نمایش داده می‌شود
        return render_template('profile.html')

    # درخواست GET: فقط نمایش پروفایل (تغییر رمز و حذف حساب)
    return render_template('profile.html')


@app.route('/profile/delete', methods=['DELETE'])
@login_required_server_session #  چک کردن لاگین
def delete_profile():
    """حذف حساب کاربری توسط خود کاربر با متد DELETE"""
    # خواندن اطلاعات از بدنه درخواست ( JSON)
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({'message': 'رمز عبور برای تایید حذف لازم است.', 'status': 'error'}), 400

    password = data.get('password')

    # بررسی رمز عبور کاربر فعلی (با g.user)
    if not g.user.check_password(password):
        # flash('رمز عبور وارد شده برای تایید حذف نادرست است.', 'danger')
        # return redirect(url_for('profile'))
        return jsonify({'message': 'رمز عبور وارد شده برای تایید حذف نادرست است.', 'status': 'error'}), 403 # Forbidden

    # جلوگیری از حذف ادمین اصلی (ID=1)
    if g.user.id == 1:
         # flash('ادمین اصلی (ID=1) اجازه حذف حساب خود را ندارد.', 'warning')
         # return redirect(url_for('profile'))
         return jsonify({'message': 'ادمین اصلی (ID=1) اجازه حذف حساب خود را ندارد.', 'status': 'error'}), 403

    # انجام عملیات حذف
    try:
        user_to_delete = g.user
        username_deleted = user_to_delete.username
        db.session.delete(user_to_delete)
        # نشست‌ها و پست‌ها باید با cascade حذف شوند
        db.session.commit()

        # پاک کردن کوکی نشست در پاسخ به کلاینت( مرورگر) (200)

        g.user = None # پاک کردن از g
        g.current_session = None

        # پاسخ موفقیت آمیز به کلاینت
        return jsonify({
            'message': f'حساب کاربری "{username_deleted}" با موفقیت برای همیشه حذف شد.',
            'status': 'success',
            'redirect_url': url_for('login', _external=True)
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting profile for user ID {g.user.id if g.user else 'Unknown'}: {e}")
        return jsonify({'message': f'خطایی هنگام حذف حساب رخ داد: {e}', 'status': 'error'}), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    صفحه ورود کاربر.
    نمایش فرم لاگین (GET).
    پردازش فرم لاگین، بررسی اعتبار کاربر، ایجاد نشست سمت سرور و تنظیم کوکی (POST).
    مدیریت 'Remember Me'.
    """
    # اگر کاربر از قبل لاگین است (مثلا با کوکی معتبر اومده)، به صفحه اصلی هدایت میشود
    if getattr(g, 'user', None):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # بررسی اینکه آیا چک‌باکس remember me انتخاب شده است
        remember_me = request.form.get('remember') == 'on'

        # یافتن کاربر بر اساس نام کاربری
        user = User.query.filter_by(username=username).first()

        # بررسی وجود کاربر و صحت رمز عبور
        if user and user.check_password(password):
            # --- ایجاد نشست جدید در سمت سرور ---
            session_id = secrets.token_urlsafe(32) # تولید سشن آی دی بصورت تصادفی
            new_session = ServerSession(
                session_id=session_id,
                user_id=user.id,
                remembered=remember_me, # ذخیره وضعیت Remember Me
                user_agent=request.user_agent.string, # ذخیره اطلاعات مرورگر
                ip_address=request.remote_addr # ذخیره آدرس IP
            )

            try:
                db.session.add(new_session)
                db.session.commit()

                flash('ورود با موفقیت انجام شد.', 'success')

                # مدیریت ریدایرکت به صفحه قبلی (next)
                next_page = request.args.get('next')
                # بررسی امنیتی برای جلوگیری از Open Redirect (**پیشنهاد چت**)
                if next_page and not is_safe_url(next_page):
                    app.logger.warning(f"Unsafe redirect attempt to '{next_page}' after login for user '{username}'.")
                    abort(400, "آدرس بازگشتی نامعتبر است.") # Bad Request

                # تعیین صفحه مقصد پس از لاگین
                # اگر next معتبر بود به آنجا، وگرنه ادمین به داشبورد و کاربر عادی به ایندکس
                redirect_target = next_page or (url_for('admin_dashboard') if user.role == 'admin' else url_for('index'))

                # ایجاد ریسپانس ریدایرکت
                response = make_response(redirect(redirect_target))

                # --- تنظیم کوکی نشست در مرورگر یوزر ---
                if remember_me:
                    # اگر Remember Me فعال است، کوکی عمر طولانی‌تری دارد (مثلا 1 روز)
                    cookie_max_age = timedelta(days=1).total_seconds()
                else:
                    # اگر Remember Me فعال نیست، کوکی به اندازه عمر نشست ست شده پیش فرض عمر دارد (مثلا 2 دقیقه)
                    cookie_max_age = app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()

                response.set_cookie(
                    'server_session_id',
                    session_id,         
                    max_age=int(cookie_max_age),
                    httponly=True,       # جلوگیری از دسترسی جاوااسکریپت به کوکی (مهم برای امنیت) (**پیشنهاد چت**)
                    #samesite='Lax'       # محافظت در برابر حملات CSRF (**پیشنهاد چت**)
                )
                return response

            except Exception as e:
                db.session.rollback()
                flash(f'خطا در ایجاد نشست سرور: {e}', 'danger')
                app.logger.error(f"Error creating server session for user '{username}': {e}")
        else:
            # اگر نام کاربری یا رمز عبور اشتباه بود
            flash('نام کاربری یا رمز عبور نامعتبر است.', 'danger')

    # درخواست GET: نمایش فرم لاگین
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    صفحه ثبت نام کاربر جدید.
    نمایش فرم ثبت نام (GET).
    پردازش فرم، ایجاد کاربر جدید با نقش 'user' و ذخیره در دیتابیس (POST).
    """
    # اگر کاربر لاگین است، نیازی به ثبت نام ندارد، به صفحه اصلی هدایت شود
    if getattr(g, 'user', None):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # اعتبار سنجی ساده ورودی‌ها
        if not username or not password:
            flash('نام کاربری و رمز عبور الزامی است.', 'warning')
            # کد وضعیت 400 (Bad Request) مناسب است
            return render_template('register.html'), 400

        # بررسی اینکه آیا نام کاربری قبلا استفاده شده است
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('این نام کاربری قبلا ثبت شده است. لطفا نام دیگری انتخاب کنید.', 'warning')
            # کد وضعیت 409 (Conflict) مناسب است
            return render_template('register.html'), 409

        # ایجاد کاربر جدید با نقش پیش‌فرض 'user'
        new_user = User(username=username, role='user')
        new_user.set_password(password) # هش کردن رمز عبور

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('ثبت نام با موفقیت انجام شد. اکنون می‌توانید وارد شوید.', 'success')
            # پس از ثبت نام موفق، کاربر را به صفحه لاگین هدایت می‌کنیم
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'خطایی هنگام ثبت نام رخ داد: {e}', 'danger')
            app.logger.error(f"Error on registration for username '{username}': {e}")
            # در صورت خطا، فرم ثبت نام دوباره نمایش داده می‌شود
            return render_template('register.html')

    # درخواست GET: نمایش فرم ثبت نام
    return render_template('register.html')


@app.route('/logout', methods=['POST'])
@login_required_server_session #  چک کردن لاگین
def logout():
    """
    پردازش درخواست خروج کاربر.
    حذف نشست مربوطه از دیتابیس سرور.
    پاک کردن کوکی نشست از مرورگر کاربر.
    """
    current_session = getattr(g, 'current_session', None)
    if current_session:
        try:
            # حذف رکورد نشست از جدول ServerSession
            db.session.delete(current_session)
            db.session.commit()
            flash('خروج با موفقیت انجام شد.', 'success')
        except Exception as e:
            db.session.rollback()
            # حتی اگر حذف نشست از دیتابیس ناموفق بود، باز هم کوکی را پاک می‌کنیم
            flash(f'خطا در حذف نشست از سرور هنگام خروج: {e}', 'danger')
            app.logger.error(f"Error deleting server session {current_session.session_id} on logout for user {g.user.id}: {e}")
    else:
        # این حالت نباید رخ دهد چون login_required_server_session باید جلوی آن را بگیرد
        flash('نشست معتبری برای خروج یافت نشد (شما از قبل خارج شده‌اید).', 'warning')
        app.logger.warning("Logout route accessed without a valid server session found in g.") # دیباگ 

    # ایجاد پاسخ ریدایرکت به صفحه لاگین
    response = make_response(redirect(url_for('login')))
    # پاک کردن کوکی نشست از مرورگر با تنظیم تاریخ انقضا در گذشته
    response.set_cookie('server_session_id', '', expires=0, httponly=True, samesite='Lax')
    
    g.user = None
    g.current_session = None
    return response


@app.route('/posts', methods=['POST'])
@login_required_server_session #  چک کردن لاگین
def submit_post():
    """پردازش فرم ثبت پست جدید."""
    post_text = request.form.get('post_text')
    if not post_text or not post_text.strip():
        flash('متن پست نمی‌تواند خالی باشد.', 'warning')
        return redirect(url_for('index'))

    # ایجاد پست جدید و انتساب آن به کاربر لاگین شده (g.user)
    new_post = Post(text=post_text.strip(), author=g.user)
    try:
        db.session.add(new_post)
        db.session.commit()
        flash('پست شما با موفقیت ثبت شد.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطایی هنگام ثبت پست رخ داد: {e}', 'danger')
        app.logger.error(f"User '{g.user.username}' (ID: {g.user.id}) failed to submit post: {e}")

    # پس از ثبت پست، به صفحه اصلی برمی‌گردیم
    return redirect(url_for('index'))


@app.route('/post/<int:post_id>/delete', methods=['DELETE'])
@login_required_server_session #  چک کردن لاگین
def delete_post(post_id):
    """حذف پست توسط نویسنده آن با متد DELETE"""
    post_to_delete = db.session.get(Post, post_id)

    if not post_to_delete:
        return jsonify({'status': 'error', 'message': 'پست مورد نظر یافت نشد.'}), 404

    # آیا کاربر لاگین شده (g.user) نویسنده پست است؟
    if post_to_delete.user_id != g.user.id:
        return jsonify({'status': 'error', 'message': 'شما اجازه حذف این پست را ندارید.'}), 403 # Forbidden

    # انجام حذف
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        # یک پاسخ JSON برای موفقیت ارسال می‌کنیم
        return jsonify({'status': 'success', 'message': 'پست شما با موفقیت حذف شد.'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"User '{g.user.username}' failed to delete own post ID {post_id}: {e}")
        return jsonify({'status': 'error', 'message': f'خطایی هنگام حذف پست رخ داد: {e}'}), 500


@app.route('/admin/post/<int:post_id>/delete', methods=['DELETE']) 
@login_required_server_session #  چک کردن لاگین
@admin_required             # چک گردن ادمین
def admin_delete_post(post_id):
    """حذف پست کاربران توسط سوپر ادمین با متد دیلیت"""

    post_to_delete = db.session.get(Post, post_id)
    
    if g.user.id != 1:
        return jsonify({'status': 'error', 'message': 'شما اجازه حذف این پست را ندارید.'}), 403 # Forbidden

    if not post_to_delete:
        return jsonify({'status': 'error', 'message': 'پست مورد نظر یافت نشد.'}), 404

    try:
        author_username = post_to_delete.author.username # نام نویسنده برای پیام
        db.session.delete(post_to_delete)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': f'پست متعلق به کاربر "{author_username}" با موفقیت توسط ادمین حذف شد.'
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Admin '{g.user.username}' failed to delete post ID {post_id}: {e}")
        return jsonify({'status': 'error', 'message': f'خطایی هنگام حذف پست توسط ادمین رخ داد: {e}'}), 500



# --- مدیریت خطاها ---
@app.errorhandler(404)
def page_not_found(e):
    """نمایش صفحه سفارشی برای خطای 404 (Not Found)."""
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    """نمایش صفحه سفارشی برای خطای 403 (Forbidden / Access Denied)."""
    message = getattr(e, 'description', 'شما اجازه دسترسی به این صفحه یا انجام این عملیات را ندارید.')
    return render_template('unauthorized.html', message=message), 403



# #--- تابع برای ایجاد اولیه دیتابیس و سوپر ادمین ---
# def init_db():
#     """
#     جداول دیتابیس را ایجاد می‌کند (اگر وجود نداشته باشند)
#     یک سوپر ادمین ('admin'/'adminpass') ایجاد می‌کند
#     """
#     with app.app_context(): 
#         try:
#             db.create_all() # ایجاد جداول User, Post, ServerSession
#             print("Database tables checked/created.")
#             # بررسی و ایجاد سوپر ادمین(ID=1)
#             if not User.query.filter_by(username='admin').first():
#                 admin_user = User(username='admin', role='admin')
#                 admin_user.set_password('adminpass') # پسورد پیش فرض سوپر ادمین
#                 db.session.add(admin_user)
#                 db.session.commit()
#                 print("Default admin user ('admin'/'adminpass') created.")
#             else:
#                 print("Default admin user already exists.")
#         except Exception as e:
#             print(f"An error occurred during DB initialization: {e}")
#             app.logger.error(f"DB Init error: {e}")



# --- اجرای سرور ---
if __name__ == '__main__':
    # ایجاد جداول دیتابیس و سوپر ادمین در هر بار اجرای برنامه (اگر نبودند)
    with app.app_context():
        db.create_all() # اطمینان از وجود جداول
         # بررسی و ایجاد سوپر ادمین(ID=1)
        if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin', role='admin')
                admin_user.set_password('adminpass') # پسورد پیش فرض سوپر ادمین
                db.session.add(admin_user)
                db.session.commit()
                print("Default admin user ('admin'/'adminpass') checked/created.")

    # اجرای سرور Flask
    app.run(host='0.0.0.0', port=5000, debug=True)