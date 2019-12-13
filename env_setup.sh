#!/bin/sh
die () {
    echo >&2 "$@"
    exit 1
}

[ "$#" -eq 3 ] || die "3 arguments required, $# provided"

REGION=$1
AWS_ACCESS_KEY_ID=$2
AWS_SECRET_ACCESS_KEY=$3

pip install requests
pip install boto3
pip install pyyaml
pip install cerberus

mkdir ~/.aws_test
touch ~/.aws_test/config && touch ~/.aws_test/credentials

echo "[default]
region=$REGION" >> ~/.aws_test/config

echo "[default]
aws_access_key_id = $AWS_ACCESS_KEY_ID
aws_secret_access_key = $AWS_SECRET_ACCESS_KEY" >> ~/.aws_test/credentials
