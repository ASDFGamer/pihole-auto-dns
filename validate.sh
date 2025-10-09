#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR

if [ ! -f ./venv/bin/activate ]; then
    python -m venv ./venv
    chmod +x ./venv/bin/activate
    . ./venv/bin/activate
    pip install black mypy flake8 pylint 
else 
    . ./venv/bin/activate
fi

echo "Black: "
black .

echo ""
echo "Mypy:"
mypy .
echo ""
echo "Flake8:"
flake8 .
echo ""
echo "Pylint"
pylint .