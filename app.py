from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lsa import LsaSummarizer

#from flask_migrate import Migrate #added this

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

### added
class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    unique_id = db.Column(db.String(32), nullable=False)
    original_text = db.Column(db.Text, nullable=False)
    reversed_text = db.Column(db.Text, nullable=False)
    actionn = db.Column(db.Text, nullable=False)
    #capitalized_text = db.Column(db.Text, nullable=False)

    user = db.relationship('User', backref=db.backref('submissions', lazy=True))
### end

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html' , username=current_user.username ) #added this second argument


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#######################

from flask import Flask, render_template, request, redirect, url_for
import hashlib



@app.route('/fullSubmission')
def fullSubmission():
    return render_template('fullSubmission.html' , username=current_user.username )

# @app.route('/result/<unique_id>')
# def result(unique_id):
#     original_text = request.args.get('original_text', '')
#     reversed_text = request.args.get('reversed_text', '')
#     return render_template('result.html', original_text=original_text, 
#         reversed_text=reversed_text, unique_id=unique_id , username=current_user.username )

@app.route('/result/<unique_id>')
def result(unique_id):
    submission = Submission.query.filter_by(unique_id=unique_id).first()
    if submission:
        return render_template('result.html', submission=submission, username=current_user.username)
    else:
        # Handle the case where the submission with the given unique_id is not found
        return render_template('result_not_found.html', username=current_user.username)

@app.route('/submitBack', methods=['POST'])
def submit():
    text = request.form.get('text', '')
    action = request.form['action']
    
    if action == 'Reverse':
        reversed_text = text[::-1]
    else:
        # Parse the input text
        parser = PlaintextParser.from_string(text, Tokenizer("english"))

        # Create an LSA summarizer
        summarizer = LsaSummarizer()

        # Generate the summary
        summary = summarizer(parser.document, sentences_count=3)  # You can adjust the number of sentences in the summary
        reversed_text = "\n".join( [str(sent) for sent in summary] )
        
    # Generate a unique ID based on the text
    unique_id = hashlib.md5(text.encode()).hexdigest()

    ### adding submission stuff
    # Create a new Submission instance
    submission = Submission(
        user=current_user,
        unique_id=unique_id,
        original_text=text,
        reversed_text=reversed_text,
        actionn = action
    )

    # Add the submission to the database
    db.session.add(submission)
    db.session.commit()

    ### end
    
    # Redirect to the result page with unique URL
    return redirect(url_for('result', unique_id=unique_id )) # , original_text=text, reversed_text=reversed_text, capitalized_text=capitalized_text

def capitalize_text(text):
    # You can replace this function with your own logic for text manipulation
    return text.upper()




#######################

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)


'''
############## test
def summyIsGood():
    
	print("hi")

	######## summy ########
 # import numpy 
	from sumy.parsers.plaintext import PlaintextParser
	from sumy.nlp.tokenizers import Tokenizer
	from sumy.summarizers.lsa import LsaSummarizer

	# Input text to be summarized
	input_text = """
	Joseph Smith Jr. (December 23, 1805 – June 27, 1844) was an American religious leader and the founder of Mormonism and the Latter Day Saint movement. Publishing the Book of Mormon at the age of 24, Smith attracted tens of thousands of followers by the time of his death fourteen years later. The religion he founded is followed to the present day by millions of global adherents and several churches, the largest of which is the Church of Jesus Christ of Latter-day Saints (LDS Church).

	Born in Sharon, Vermont, Smith moved with his family to the western region of New York State, following a series of crop failures in 1816. Living in an area of intense religious revivalism during the Second Great Awakening, Smith reported experiencing a series of visions. The first of these was in 1820, when he saw "two personages" (whom he eventually described as God the Father and Jesus Christ). In 1823, he said he was visited by an angel who directed him to a buried book of golden plates inscribed with a Judeo-Christian history of an ancient American civilization. In 1830, Smith published the Book of Mormon, which he described as an English translation of those plates. The same year he organized the Church of Christ, calling it a restoration of the early Christian Church. Members of the church were later called "Latter Day Saints" or "Mormons".

	In 1831, Smith and his followers moved west, planning to build a communal Zion in the American heartland. They first gathered in Kirtland, Ohio, and established an outpost in Independence, Missouri, which was intended to be Zion's "center place". During the 1830s, Smith sent out missionaries, published revelations, and supervised construction of the Kirtland Temple. Because of the collapse of the church-sponsored Kirtland Safety Society, violent skirmishes with non-Mormon Missourians, and the Mormon extermination order, Smith and his followers established a new settlement at Nauvoo, Illinois, of which he was the spiritual and political leader. In 1844, when the Nauvoo Expositor criticized Smith's power and his practice of polygamy, Smith and the Nauvoo City Council ordered the destruction of its printing press, inflaming anti-Mormon sentiment. Fearing an invasion of Nauvoo, Smith rode to Carthage, Illinois, to stand trial, but was shot and killed by a mob that stormed the jailhouse.
	"""

	# Parse the input text
	parser = PlaintextParser.from_string(input_text, Tokenizer("english"))

	# Create an LSA summarizer
	summarizer = LsaSummarizer()

	# Generate the summary
	summary = summarizer(parser.document, sentences_count=3)  # You can adjust the number of sentences in the summary

	# Output the summary
	print("Original Text:")
	print(input_text)
	print("\nSummary:")
	for sentence in summary:
		print(sentence)
    type(sentence)
    str(sentence).to_string()
'''