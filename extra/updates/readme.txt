The update_users script needs to be run from a virtualenv after installing the requirements.txt dependencies.

virtualenv sandbox
. sandbox/bin/activate
pip install -r requirements.txt
python update_users.py
