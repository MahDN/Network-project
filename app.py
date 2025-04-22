# app.py
import os
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse, urljoin

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secure-dev-secret-key') # حتما در محیط واقعی تغییر دهید
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # زمان انقضای نشست برای لاگ‌اوت خودکار

# --- Database Configuration ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # نام تابعی که صفحه لاگین را نمایش می‌دهد
login_manager.login_message = "برای دسترسی به این صفحه، لطفا ابتدا وارد شوید."
login_manager.login_message_category = "info"

# ---> اضافه کردن این تابع برای کنترل کش <---
@app.after_request
def set_response_headers(response):
    """
    افزودن هدر برای جلوگیری از کش شدن صفحات در مرورگر،
    مخصوصا بعد از لاگ اوت یا برای صفحات حساس.
    """
    # این هدرها رو به تمام پاسخ‌های HTML موفق اضافه می‌کنیم
    # تا مطمئن شویم مرورگر همیشه نسخه جدید صفحه را از سرور می‌گیرد.
    if response.status_code == 200 and response.mimetype == 'text/html':
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache' # سازگاری با HTTP/1.0
        response.headers['Expires'] = '0' # برای پراکسی‌ها
    return response

# --- Database Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user') # 'user' or 'admin'
    posts = db.relationship('Post', backref='author', lazy=True, cascade="all, delete-orphan") # cascade برای حذف پست‌ها هنگام حذف کاربر

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} (Role: {self.role})>'

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Post {self.id} by User {self.user_id}>'

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Helper Functions ---

def admin_required(func):
    """Decorator برای محدود کردن دسترسی به ادمین‌ها"""
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return render_template('unauthorized.html', message="شما دسترسی ادمین برای مشاهده این صفحه را ندارید."), 403
        return func(*args, **kwargs)
    return decorated_view

def is_safe_url(target):
    """جلوگیری از حملات Open Redirect"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# --- Routes ---

@app.route('/')
@login_required
def index():
    """صفحه اصلی - نمایش پست‌ها"""
    # نمایش 30 پست اخیر
    posts_to_show = Post.query.order_by(Post.timestamp.desc()).limit(30).all()
    return render_template('index.html', posts=posts_to_show)

@app.route('/admin')
@login_required
@admin_required # فقط ادمین
def admin_dashboard():
    """داشبورد ادمین - نمایش کاربران و فرم افزودن کاربر"""
    all_users = User.query.order_by(User.role, User.username).all() # مرتب‌سازی بر اساس نقش و نام
    return render_template('admin.html', users=all_users)

# ----> مسیر جدید برای پردازش فرم افزودن کاربر توسط ادمین <----
@app.route('/admin/create_user', methods=['POST'])
@login_required
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
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
        flash(f"کاربر '{username}' با نقش '{role}' با موفقیت ایجاد شد.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطا در ایجاد کاربر: {e}', 'danger')
        app.logger.error(f"Admin '{current_user.username}' failed to create user '{username}': {e}")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/set_role', methods=['POST'])
@login_required
@admin_required
def admin_set_user_role(user_id):
    """تغییر نقش کاربر توسط ادمین"""
    admin_password = request.form.get('admin_password')
    new_role = request.form.get('new_role')

    # 1. بررسی رمز عبور ادمین فعلی
    if not current_user.check_password(admin_password):
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
    if user_to_modify.id == current_user.id:
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
        app.logger.error(f"Admin '{current_user.username}' failed to set role for user ID {user_id}: {e}")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    """حذف کاربر توسط ادمین"""
    admin_password = request.form.get('admin_password')

    # 1. بررسی رمز عبور ادمین فعلی
    if not current_user.check_password(admin_password):
        flash('رمز عبور ادمین نادرست است.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # 2. یافتن کاربری که قرار است حذف شود
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('کاربر مورد نظر یافت نشد.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # 3. جلوگیری از حذف خود ادمین
    if user_to_delete.id == current_user.id:
        flash('شما نمی‌توانید حساب کاربری خود را حذف کنید.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # 4. انجام حذف کاربر (و پست‌هایش به خاطر cascade)
    try:
        username_deleted = user_to_delete.username # نام را قبل از حذف نگه داریم
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f"کاربر '{username_deleted}' با موفقیت حذف شد.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطا در حذف کاربر: {e}', 'danger')
        app.logger.error(f"Admin '{current_user.username}' failed to delete user ID {user_id}: {e}")

    return redirect(url_for('admin_dashboard'))
# این route را به بخش Routes در app.py اضافه کنید

@app.route('/profile', methods=['GET', 'POST'])
@login_required # فقط کاربران لاگین شده
def profile():
    """نمایش پروفایل و فرم تغییر رمز عبور"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # 1. بررسی رمز عبور فعلی
        if not current_user.check_password(current_password):
            flash('رمز عبور فعلی نادرست است.', 'danger')
        # 2. بررسی خالی نبودن رمز جدید
        elif not new_password:
             flash('رمز عبور جدید نمی‌تواند خالی باشد.', 'warning')
        # 3. بررسی تطابق رمز جدید و تکرار آن
        elif new_password != confirm_new_password:
            flash('رمز عبور جدید و تکرار آن با هم مطابقت ندارند.', 'warning')
        # 4. همه چیز درست است، رمز را تغییر بده
        else:
            try:
                current_user.set_password(new_password) # هش کردن و تنظیم رمز جدید
                db.session.commit() # ذخیره تغییر در دیتابیس
                flash('رمز عبور شما با موفقیت تغییر کرد.', 'success')
                # می‌توانید کاربر را بعد از تغییر رمز لاگ‌اوت کنید (اختیاری ولی امن‌تر)
                # logout_user()
                # session.clear()
                # return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash(f'خطایی هنگام تغییر رمز عبور رخ داد: {e}', 'danger')
                app.logger.error(f"Error changing password for user '{current_user.username}': {e}")

        # در صورت بروز خطا یا موفقیت (اگر ریدایرکت نشد)، دوباره فرم را نمایش بده
        # این باعث می‌شود پیام‌های فلش نمایش داده شوند
        # return redirect(url_for('profile')) # این باعث می‌شود پیام فلش دیده شود ولی فیلدها خالی شوند
        # نمایش دوباره همان صفحه بهتر است تا کاربر خطا را ببیند
        return render_template('profile.html')


    # درخواست GET: فقط نمایش فرم
    return render_template('profile.html')
    
    
    # این route را به بخش Routes در app.py اضافه کنید

@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_profile():
    """حذف حساب کاربری توسط خود کاربر"""
    password = request.form.get('password')

    # 1. بررسی رمز عبور کاربر فعلی
    if not current_user.check_password(password):
        flash('رمز عبور وارد شده برای تایید حذف نادرست است.', 'danger')
        return redirect(url_for('profile'))

    # 2. جلوگیری از حذف ادمین اصلی (ID=1)
    #    این بررسی اضافی لازم است چون کاربر ممکن است مستقیما POST ارسال کند
    if current_user.id == 1:
         flash('ادمین اصلی (ID=1) اجازه حذف حساب خود را ندارد.', 'warning')
         return redirect(url_for('profile'))

    # 3. انجام عملیات حذف
    try:
        user_to_delete = current_user # کاربر فعلی را می‌گیریم
        username_deleted = user_to_delete.username

        # ابتدا کاربر را لاگ‌اوت می‌کنیم
        logout_user()
        session.clear()

        # سپس کاربر را از دیتابیس حذف می‌کنیم (پست‌ها هم cascade می‌شوند)
        db.session.delete(user_to_delete)
        db.session.commit()

        flash(f'حساب کاربری "{username_deleted}" با موفقیت برای همیشه حذف شد.', 'success')
        # کاربر به صفحه لاگین هدایت می‌شود چون لاگ‌اوت شده
        return redirect(url_for('login'))

    except Exception as e:
        db.session.rollback()
        # اگر خطایی رخ داد، کاربر هنوز لاگین است (چون کامیت نشد)
        # باید سعی کنیم کاربر را دوباره لاگین کنیم یا حداقل پیام خطا بدهیم
        # ساده‌ترین کار نمایش خطا در صفحه پروفایل است
        flash(f'خطایی هنگام حذف حساب رخ داد: {e}', 'danger')
        app.logger.error(f"Error deleting profile for user '{current_user.username}': {e}") # اینجا current_user ممکن است معتبر نباشد اگر logout شده باشد
        # بهتر است فقط به لاگین ریدایرکت کنیم چون وضعیت نامشخص است
        # یا تلاش برای بازیابی وضعیت کاربر اگر امکان‌پذیر باشد
        # در این مثال ساده، به لاگین هدایت می‌کنیم
        return redirect(url_for('login')) # یا profile اگر فکر می‌کنید کاربر هنوز معتبر است
        
        
@app.route('/login', methods=['GET', 'POST'])
def login():
    """صفحه ورود کاربر"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            if not remember:
                session.permanent = True # فعال کردن انقضای خودکار

            flash('ورود با موفقیت انجام شد.', 'success')
            next_page = request.args.get('next')
            # اطمینان از امن بودن آدرس next_page
            if next_page and not is_safe_url(next_page):
                return abort(400)

            # هدایت به صفحه مناسب
            if user.role == 'admin':
                 # ادمین به داشبورد ادمین هدایت شود مگر اینکه next_page معتبر دیگری باشد
                return redirect(next_page or url_for('admin_dashboard'))
            else:
                return redirect(next_page or url_for('index'))
        else:
            flash('نام کاربری یا رمز عبور نامعتبر است.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """صفحه ثبت نام کاربر جدید (همیشه با نقش 'user')"""
    if current_user.is_authenticated:
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
            return render_template('register.html'), 409

        # کاربران جدید همیشه با نقش 'user' ایجاد می‌شوند
        new_user = User(username=username, role='user')
        new_user.set_password(password)

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

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """خروج کاربر"""
    logout_user()
    session.clear()
    resp = redirect(url_for('login'))
    # پاک‌سازی کوکی remember_token (کوکی پیش‌فرض Flask-Login برای remember me)
    resp = app.make_response(resp)
    resp.set_cookie('remember_token', '', expires=0)

    flash('خروج با موفقیت انجام شد.', 'success')
    return resp

@app.route('/posts', methods=['POST'])
@login_required
def submit_post():
    """ثبت پست جدید"""
    post_text = request.form.get('post_text')
    if not post_text:
        flash('متن پست نمی‌تواند خالی باشد.', 'warning')
        return redirect(url_for('index'))

    new_post = Post(text=post_text, author=current_user)
    try:
        db.session.add(new_post)
        db.session.commit()
        flash('پست شما با موفقیت ثبت شد.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطایی هنگام ثبت پست رخ داد: {e}', 'danger')
        app.logger.error(f"User '{current_user.username}' failed to submit post: {e}")

    return redirect(url_for('index'))

# این route را به بخش Routes در app.py اضافه کنید

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    """حذف پست توسط نویسنده آن"""
    post_to_delete = db.session.get(Post, post_id)

    if not post_to_delete:
        flash('پست مورد نظر یافت نشد.', 'danger')
        # return redirect(url_for('index')) # یا abort(404)
        abort(404)

    # ---> بررسی مهم: آیا کاربر فعلی نویسنده این پست است؟ <---
    if post_to_delete.user_id != current_user.id:
        flash('شما اجازه حذف این پست را ندارید.', 'danger')
        # return redirect(url_for('index')) # یا abort(403)
        abort(403) # Forbidden

    # انجام حذف
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash('پست شما با موفقیت حذف شد.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'خطایی هنگام حذف پست رخ داد: {e}', 'danger')
        app.logger.error(f"User '{current_user.username}' failed to delete own post ID {post_id}: {e}")

    return redirect(url_for('index'))

# این route را به بخش Routes در app.py اضافه کنید

@app.route('/admin/post/<int:post_id>/delete', methods=['POST'])
@login_required
def admin_delete_post(post_id):
    """حذف هر پستی توسط ادمین اصلی (ID=1)"""

    # ---> بررسی مهم: آیا کاربر فعلی ادمین اصلی (ID=1) است؟ <---
    if current_user.id != 1:
        flash('شما اجازه انجام این عملیات را ندارید.', 'danger')
        abort(403) # Forbidden

    post_to_delete = db.session.get(Post, post_id)

    if not post_to_delete:
        flash('پست مورد نظر یافت نشد.', 'danger')
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
        app.logger.error(f"SuperAdmin (ID=1) failed to delete post ID {post_id}: {e}")

    return redirect(url_for('index'))
    
    
# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    # این errorhandler زمانی فراخوانی می‌شود که abort(403) صدا زده شود
    # یا دکوراتور admin_required دسترسی را رد کند
    # اگر پیام خاصی در abort پاس داده شود، اینجا قابل دسترسی است (ولی ما در دکوراتور مستقیم قالب را رندر کردیم)
    return render_template('unauthorized.html', message="شما اجازه دسترسی به این صفحه را ندارید."), 403

# --- Database Initialization ---
def init_db():
    """ایجاد جداول دیتابیس و کاربر ادمین اولیه (اگر وجود نداشته باشند)"""
    with app.app_context():
        try:
            db.create_all()
            print("Database tables checked/created.")
            # ایجاد کاربر ادمین پیش‌فرض
            if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin', role='admin')
                admin_user.set_password('adminpass') # ---> رمز عبور ادمین اولیه <---
                db.session.add(admin_user)
                db.session.commit()
                print("Default admin user ('admin'/'adminpass') created.")
        except Exception as e:
            print(f"An error occurred during DB initialization: {e}")
            app.logger.error(f"DB Init error: {e}")


# --- Main Execution ---
if __name__ == '__main__':
    init_db() # اجرای تابع ساخت دیتابیس قبل از اجرای وب سرور
    # debug=True برای توسعه مناسب است، در محیط عملیاتی False باشد
    # host='0.0.0.0' اجازه دسترسی از سایر دستگاه‌های شبکه را می‌دهد
    app.run(host='0.0.0.0', port=62159, debug=True)