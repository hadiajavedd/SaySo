import os      # used to build file paths so flask finds the right folders
import base64  # used to convert the qr code image into text so it can be sent to the browser
import json    # used to save and read answers as text in the database
import socket  # used to find the machines local ip address for the share url
import secrets # used to generate the random token for password resets
import qrcode  # used to generate the qr code image on the share page

from io import BytesIO                    # used to handle the qr code image in memory without saving it as a file
from datetime import datetime, timedelta, timezone  # used for timestamps and calculating the 1 hour reset token expiry

from flask import Flask, request, session, redirect, jsonify, render_template, url_for   # the main flask tools used to build routes and handle requests
from flask_sqlalchemy import SQLAlchemy                                                  # used to talk to the database using python instead of sql
from sqlalchemy import text, func                                                        # used for raw sql queries and functions like lowercase comparison
from sqlalchemy.exc import IntegrityError                                                # used to catch duplicate username errors when saving to the database
from werkzeug.security import generate_password_hash, check_password_hash                # used to hash passwords and check them on login


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = "dev-secret-key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'feedback.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# MODELS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=True)
    # email_verified is kept to satisfy the existing database schema
    email_verified = db.Column(db.Boolean, default=True, nullable=False)
    reset_token = db.Column(db.String(200), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    # cascade delete means if a user is deleted all their questionnaires are deleted too
    questionnaires = db.relationship(
        "Questionnaire",
        backref="user",
        cascade="all, delete"
    )


class Questionnaire(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_opened = db.Column(db.DateTime, default=datetime.utcnow)

    # cascade delete removes all questions and responses if the questionnaire is deleted
    questions = db.relationship(
        "Question",
        backref="questionnaire",
        cascade="all, delete"
    )

    responses = db.relationship(
        "Response",
        backref="questionnaire",
        cascade="all, delete"
    )


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    qtype = db.Column(db.String(20), nullable=False)
    questionnaire_id = db.Column(
        db.Integer,
        db.ForeignKey('questionnaire.id'),
        nullable=False
    )


class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    questionnaire_id = db.Column(
        db.Integer,
        db.ForeignKey('questionnaire.id'),
        nullable=False
    )
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    # all answers are stored together as a json string in one column
    answers_json = db.Column(db.Text, nullable=False)


# SCHEMA HELPERS
# these run on startup and add any missing columns to the database
# needed because the database was created by an older version of the app

def ensure_response_schema():
    db.create_all()

    table_check = db.session.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name='response'")
    ).fetchone()

    if not table_check:
        return

    columns = db.session.execute(text("PRAGMA table_info(response)")).fetchall()
    column_names = [c[1] for c in columns]

    if "answers_json" not in column_names:
        db.session.execute(text("ALTER TABLE response ADD COLUMN answers_json TEXT"))
        db.session.commit()

    if "submitted_at" not in column_names:
        db.session.execute(text("ALTER TABLE response ADD COLUMN submitted_at DATETIME"))
        db.session.commit()


def ensure_user_schema():
    db.create_all()

    table_check = db.session.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
    ).fetchone()

    if not table_check:
        return

    columns = db.session.execute(text("PRAGMA table_info(user)")).fetchall()
    column_names = [c[1] for c in columns]

    if "is_admin" not in column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
        db.session.commit()

    if "email" not in column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN email VARCHAR(200)"))
        db.session.commit()

    if "reset_token" not in column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN reset_token VARCHAR(200)"))
        db.session.commit()

    if "reset_token_expiry" not in column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN reset_token_expiry DATETIME"))
        db.session.commit()

    # if no admin exists yet make the first user an admin
    admin_exists = db.session.execute(
        text("SELECT id FROM user WHERE is_admin = 1 LIMIT 1")
    ).fetchone()

    if not admin_exists:
        first_user = db.session.execute(
            text("SELECT id FROM user ORDER BY id ASC LIMIT 1")
        ).fetchone()

        if first_user:
            db.session.execute(
                text("UPDATE user SET is_admin = 1 WHERE id = :user_id"),
                {"user_id": first_user[0]}
            )
            db.session.commit()


# HELPERS

def to_utc_iso(dt):
    # add UTC timezone so browser converts correctly
    if not dt:
        return None
    return dt.replace(tzinfo=timezone.utc).isoformat()

def get_local_ip():
    # finds the machines local ip so the share url works on the same wifi network
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def build_share_url(questionnaire_id):
    # if running locally swap 127.0.0.1 for the real local ip so other devices can open the link
    host = request.host.split(":")[0]
    port = request.host.split(":")[1] if ":" in request.host else "5000"

    if host in ["127.0.0.1", "localhost"]:
        return f"http://{get_local_ip()}:{port}/take-questionnaire/{questionnaire_id}"

    return url_for("take_questionnaire_page", id=questionnaire_id, _external=True)


def admin_only():
    # blocks non-admins from accessing admin pages
    if "user_id" not in session:
        return redirect("/")

    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return redirect("/")

    if not user.is_admin:
        session["is_admin"] = False
        return redirect("/homepage")

    return None


def admin_count():
    return User.query.filter_by(is_admin=True).count()


def is_last_admin(user):
    # prevents the last admin from being deleted or demoted
    return user.is_admin and admin_count() <= 1


def has_another_admin(current_user_id):
    return User.query.filter(
        User.is_admin == True,
        User.id != current_user_id
    ).count() > 0


# STARTUP

with app.app_context():
    ensure_response_schema()
    ensure_user_schema()


# AUTH ROUTES

@app.route('/', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()

        if not user or not check_password_hash(user.password, request.form["password"]):
            return render_template("login.html", error="Invalid username or password.")

        session["user_id"] = user.id
        session["username"] = user.username
        session["is_admin"] = user.is_admin
        return redirect("/homepage")

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        existing_user = User.query.filter(
            func.lower(User.username) == username.lower()
        ).first()
        if existing_user:
            return render_template("signup.html", error="Username already taken.")

        existing_email = User.query.filter(
            func.lower(User.email) == email
        ).first()
        if existing_email:
            return render_template("signup.html", error="An account with that email already exists.")

        # check the password is at least 6 characters long before creating the account
        if len(password) < 6:
            return render_template("signup.html", error="Password must be at least 6 characters.")

        hashed_password = generate_password_hash(password)
        is_first_user = User.query.count() == 0  # the very first user is automatically made an admin

        new_user = User(
            username=username,
            password=hashed_password,
            email=email,
            is_admin=is_first_user
        )
        db.session.add(new_user)
        db.session.commit()

        return render_template("login.html", success="Account created successfully! You can now log in.")

    return render_template("signup.html")


# in a real app this would send a reset link to the users email instead of redirecting directly
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()

        user = User.query.filter(
            func.lower(User.username) == username.lower(),
            func.lower(User.email) == email
        ).first()

        if not user:
            return render_template(
                "forgot_password.html",
                error="No account matches that username and email."
            )

        # creates a secure temporary 1hr link for resetting a password
        token = secrets.token_urlsafe(32)
        user.reset_token = token
        user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()

        return redirect(f"/reset-password/{token}")

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_page(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
        return render_template("login.html", error="Password reset link is invalid or has expired.")

    if request.method == "POST":
        new_password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not new_password or not confirm_password:
            return render_template("reset_password.html", token=token, error="Please fill in both fields.")

        if new_password != confirm_password:
            return render_template("reset_password.html", token=token, error="Passwords do not match.")

        if len(new_password) < 6:
            return render_template("reset_password.html", token=token, error="Password must be at least 6 characters.")

        user.password = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()

        return render_template("login.html", success="Password updated! You can now log in.")

    return render_template("reset_password.html", token=token)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/delete-account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return redirect("/")

    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return redirect("/")

    if is_last_admin(user):
        return redirect("/profile")

    db.session.delete(user)
    db.session.commit()
    session.clear()
    return redirect("/")


# PAGE ROUTES

@app.route("/homepage")
def homepage():
    if "user_id" not in session:
        return redirect("/")
    return render_template("homepage.html")


@app.route("/profile")
def profile_page():
    if "user_id" not in session:
        return redirect("/")
    return render_template("profile.html")


@app.route("/create-questionnaire")
def create_questionnaire_page():
    if "user_id" not in session:
        return redirect("/")
    return render_template("create_questionnaire.html")


@app.route("/insights")
def insights_page():
    if "user_id" not in session:
        return redirect("/")
    return render_template("insights.html")


@app.route("/view-questionnaire/<int:id>")
def view_questionnaire_page(id):
    if "user_id" not in session:
        return redirect("/")

    q = Questionnaire.query.get(id)
    if not q or q.user_id != session["user_id"]:
        return "Questionnaire not found", 404

    q.last_opened = datetime.utcnow()
    db.session.commit()

    return render_template("view_questionnaire.html", questionnaire=q)


@app.route("/edit-questionnaire/<int:id>")
def edit_questionnaire_page(id):
    if "user_id" not in session:
        return redirect("/")

    q = Questionnaire.query.get(id)
    if not q or q.user_id != session["user_id"]:
        return "Questionnaire not found", 404

    q.last_opened = datetime.utcnow()
    db.session.commit()

    return render_template("edit_questionnaire.html")


@app.route("/take-questionnaire/<int:id>", methods=["GET", "POST"])
def take_questionnaire_page(id):
    q = Questionnaire.query.get(id)
    if not q:
        return "Questionnaire not found", 404

    q.last_opened = datetime.utcnow()
    db.session.commit()

    if request.method == "POST":
        answers = {}
        questions_sorted = sorted(q.questions, key=lambda x: x.id)

        for ques in questions_sorted:
            key = f"q{ques.id}"
            answers[str(ques.id)] = request.form.get(key, "")

        # save all answers as a json string in the database
        r = Response(
            questionnaire_id=q.id,
            answers_json=json.dumps(answers)
        )
        db.session.add(r)
        db.session.commit()

        return render_template("thank_you.html", questionnaire=q)

    return render_template("take_questionnaire.html", questionnaire=q)


@app.route("/responses/<int:id>")
def view_responses_page(id):
    if "user_id" not in session:
        return redirect("/")

    q = Questionnaire.query.get(id)
    if not q or q.user_id != session["user_id"]:
        return "Questionnaire not found", 404

    questions_sorted = sorted(q.questions, key=lambda x: x.id)
    responses = Response.query.filter_by(questionnaire_id=id).order_by(Response.submitted_at.desc()).all()

    rows = []
    for r in responses:
        try:
            answers = json.loads(r.answers_json) if r.answers_json else {}
        except Exception:
            answers = {}

        row = []
        for ques in questions_sorted:
            row.append(answers.get(str(ques.id), ""))
        rows.append({
            "submitted_at": r.submitted_at,
            "answers": row
        })

    return render_template("view_responses.html", questionnaire=q, questions=questions_sorted, responses=rows)


@app.route("/share/<int:id>")
def share_questionnaire_page(id):
    if "user_id" not in session:
        return redirect("/")

    q = Questionnaire.query.get(id)
    if not q or q.user_id != session["user_id"]:
        return "Questionnaire not found", 404

    share_url = build_share_url(id)

    # generate the qr code and convert it to base64 so it can be embedded in the html
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(share_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

    return render_template(
        "share_questionnaire.html",
        qr_code=qr_base64,
        share_url=share_url,
        q_title=q.title
    )


@app.route("/help")
def help_page():
    if "user_id" not in session:
        return redirect("/")
    return render_template("help.html")


# ADMIN ROUTES

@app.route("/admin")
def admin_dashboard():
    block = admin_only()
    if block:
        return block

    total_users = User.query.count()
    total_questionnaires = Questionnaire.query.count()
    total_responses = Response.query.count()

    recent_users = User.query.order_by(User.id.desc()).limit(5).all()
    recent_questionnaires = Questionnaire.query.order_by(Questionnaire.created_at.desc()).limit(5).all()
    recent_responses = Response.query.order_by(Response.submitted_at.desc()).limit(5).all()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_questionnaires=total_questionnaires,
        total_responses=total_responses,
        recent_users=recent_users,
        recent_questionnaires=recent_questionnaires,
        recent_responses=recent_responses
    )


@app.route("/admin/users")
def admin_users():
    block = admin_only()
    if block:
        return block

    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/questionnaires")
def admin_questionnaires():
    block = admin_only()
    if block:
        return block

    questionnaires = Questionnaire.query.order_by(Questionnaire.created_at.desc()).all()
    return render_template("admin_questionnaires.html", questionnaires=questionnaires)


@app.route("/admin/responses")
def admin_responses():
    block = admin_only()
    if block:
        return block

    responses = Response.query.order_by(Response.submitted_at.desc()).all()
    return render_template("admin_responses.html", responses=responses)


@app.route("/admin/make-admin/<int:id>", methods=["POST"])
def admin_make_admin(id):
    block = admin_only()
    if block:
        return block

    user = User.query.get(id)
    if not user:
        return redirect("/admin/users")

    user.is_admin = True
    db.session.commit()
    return redirect("/admin/users")


# if the admin removes their own access they get logged out
@app.route("/admin/remove-admin/<int:id>", methods=["POST"])
def admin_remove_admin(id):
    block = admin_only()
    if block:
        return block

    user = User.query.get(id)
    if not user:
        return redirect("/admin/users")

    if is_last_admin(user):
        return redirect("/admin/users")

    removing_own_admin = (user.id == session.get("user_id"))

    user.is_admin = False
    db.session.commit()

    if removing_own_admin:
        session.clear()
        return redirect("/")

    return redirect("/admin/users")


@app.route("/admin/delete-user/<int:id>", methods=["POST"])
def admin_delete_user(id):
    block = admin_only()
    if block:
        return block

    user = User.query.get(id)
    if not user:
        return redirect("/admin/users")

    if id == session.get("user_id"):
        return redirect("/admin/users")

    if is_last_admin(user):
        return redirect("/admin/users")

    db.session.delete(user)
    db.session.commit()
    return redirect("/admin/users")


@app.route("/admin/delete-questionnaire/<int:id>", methods=["POST"])
def admin_delete_questionnaire(id):
    block = admin_only()
    if block:
        return block

    q = Questionnaire.query.get(id)
    if q:
        db.session.delete(q)
        db.session.commit()

    return redirect("/admin/questionnaires")


@app.route("/admin/delete-response/<int:id>", methods=["POST"])
def admin_delete_response(id):
    block = admin_only()
    if block:
        return block

    r = Response.query.get(id)
    if r:
        db.session.delete(r)
        db.session.commit()

    return redirect("/admin/responses")


# API ROUTES

@app.route("/api/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    user = User.query.get(session["user_id"])
    return jsonify({
        "username": user.username if user else session.get("username", ""),
        "is_admin": user.is_admin if user else False
    })


@app.route("/api/my-questionnaires")
def api_my_questionnaires():
    if "user_id" not in session:
        return jsonify([])

    questionnaires = Questionnaire.query.filter_by(
        user_id=session["user_id"]
    ).order_by(Questionnaire.created_at.desc()).all()

    return jsonify([
    {
        "id": q.id,
        "title": q.title,
        "created_at": to_utc_iso(q.created_at),
        "last_opened": to_utc_iso(q.last_opened)
    }
    for q in questionnaires
])


# calculates answer counts, activity by day, and most common answers per question
@app.route("/api/insights/<int:id>")
def api_insights(id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    q = Questionnaire.query.get(id)
    if not q or q.user_id != session["user_id"]:
        return jsonify({"error": "Questionnaire not found"}), 404

    questions_sorted = sorted(q.questions, key=lambda x: x.id)
    responses = Response.query.filter_by(
        questionnaire_id=id
    ).order_by(Response.submitted_at.asc()).all()

    total_responses = len(responses)
    total_questions = len(questions_sorted)

    answer_counts = {}
    activity_by_day = {}
    question_breakdown = []

    for response in responses:
        day_key = response.submitted_at.strftime("%d %b")
        activity_by_day[day_key] = activity_by_day.get(day_key, 0) + 1

        try:
            answers = json.loads(response.answers_json) if response.answers_json else {}
        except Exception:
            answers = {}

        for key, value in answers.items():
            cleaned = str(value).strip()
            if cleaned:
                answer_counts[cleaned] = answer_counts.get(cleaned, 0) + 1

    for question in questions_sorted:
        per_question_counts = {}

        for response in responses:
            try:
                answers = json.loads(response.answers_json) if response.answers_json else {}
            except Exception:
                answers = {}

            answer = str(answers.get(str(question.id), "")).strip()
            if answer:
                per_question_counts[answer] = per_question_counts.get(answer, 0) + 1

        if per_question_counts:
            most_common_answer = max(per_question_counts, key=per_question_counts.get)
            total_answers = sum(per_question_counts.values())
        else:
            most_common_answer = None
            total_answers = 0

        question_breakdown.append({
            "question": question.text,
            "most_common_answer": most_common_answer,
            "total_answers": total_answers
        })

    if answer_counts:
        sorted_answers = sorted(answer_counts.items(), key=lambda x: x[1], reverse=True)
        top_answer = sorted_answers[0][0]
        popular_answers = [
            {"label": label, "count": count}
            for label, count in sorted_answers[:4]  # only return top 4 for the bar chart
        ]
    else:
        top_answer = None
        popular_answers = []

    if activity_by_day:
        sorted_activity = sorted(activity_by_day.items(), key=lambda x: x[1], reverse=True)
        top_day = sorted_activity[0][0]
        activity = [
            {"day": day, "count": count}
            for day, count in activity_by_day.items()
        ]
    else:
        top_day = None
        activity = []

    return jsonify({
        "total_responses": total_responses,
        "total_questions": total_questions,
        "top_answer": top_answer,
        "top_day": top_day,
        "popular_answers": popular_answers,
        "activity": activity,
        "question_breakdown": question_breakdown
    })


@app.route("/api/questionnaire/<int:id>")
def api_get_questionnaire(id):
    q = Questionnaire.query.get(id)
    return jsonify({
        "title": q.title,
        "questions": [{"text": x.text, "qtype": x.qtype} for x in q.questions]
    })


# deletes old questions and saves the updated ones
@app.route("/api/questionnaire/<int:id>", methods=["PUT"])
def api_edit_questionnaire(id):
    q = Questionnaire.query.get(id)
    if not q or q.user_id != session.get("user_id"):
        return jsonify({"error": "Not found"}), 404

    data = request.get_json()
    q.title = data["title"]

    Question.query.filter_by(questionnaire_id=q.id).delete()
    for ques in data["questions"]:
        db.session.add(Question(
            text=ques["text"],
            qtype=ques["qtype"],
            questionnaire_id=q.id
        ))

    db.session.commit()
    return jsonify({"success": True})


@app.route("/api/questionnaires", methods=["POST"])
def api_create_questionnaire():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json()
    q = Questionnaire(title=data["title"], user_id=session["user_id"])
    db.session.add(q)
    db.session.commit()

    for ques in data["questions"]:
        db.session.add(Question(
            text=ques["text"],
            qtype=ques["qtype"],
            questionnaire_id=q.id
        ))

    db.session.commit()
    return jsonify({"id": q.id})


@app.route("/api/questionnaires/<int:id>", methods=["DELETE"])
def api_delete_questionnaire(id):
    q = Questionnaire.query.get(id)
    if q and q.user_id == session.get("user_id"):
        db.session.delete(q)
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"error": "Not found"}), 404


@app.route("/api/update-username", methods=["POST"])
def api_update_username():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 401

    data = request.get_json()
    new_username = data.get("username", "").strip()

    if not new_username:
        return jsonify({"success": False, "error": "Username is required"}), 400

    user = User.query.get(session["user_id"])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    existing_user = User.query.filter(
        func.lower(User.username) == new_username.lower(),
        User.id != user.id
    ).first()

    if existing_user:
        return jsonify({"success": False, "error": "Username already exists"}), 400

    user.username = new_username

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"success": False, "error": "Username already exists"}), 400

    session["username"] = new_username
    return jsonify({"success": True, "username": new_username})


@app.route("/api/change-password", methods=["POST"])
def api_change_password():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 401

    data = request.get_json()
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not current_password or not new_password:
        return jsonify({"success": False, "error": "Both password fields are required"}), 400

    user = User.query.get(session["user_id"])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    if not check_password_hash(user.password, current_password):
        return jsonify({"success": False, "error": "Current password is incorrect"}), 400

    user.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)