Installation

python -m venv venv

source venv/Scripts/activate
source venv/bin/activate

pip install -r requirements.txt

uvicorn main:app --reload --port 8000

Then,

export the environment file.

N.B: It requires to install sqlite3
