#!/bin/bash
# EC2 > Launch instance > Advanced details > User data.
# 1) Replace YOUR-BUCKET-NAME below.  2) Paste the whole script.
# On first boot it installs Python, TenSEAL and boto3; on EVERY start the service downloads the
# newest server code from s3://BUCKET/code/ and runs it with the instance's IAM role.
BUCKET="fyp-demo"
set -e
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
if [ ! -f /opt/fhe/READY ]; then
  apt-get update
  apt-get install -y python3-venv
  mkdir -p /opt/fhe
  python3 -m venv /opt/fhe/venv
  /opt/fhe/venv/bin/pip install tenseal boto3
  touch /opt/fhe/READY
fi
cat > /opt/fhe/fetch_code.py <<'PY'
import sys
import boto3
s3 = boto3.client("s3")
for name in ("common.py", "cloud_server.py"):
    s3.download_file(sys.argv[1], "code/" + name, "/opt/fhe/" + name)
PY
cat > /etc/systemd/system/fhe.service <<UNIT
[Unit]
Description=FHE cloud demo server
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/fhe
Environment=AWS_DEFAULT_REGION=${REGION}
ExecStartPre=/opt/fhe/venv/bin/python /opt/fhe/fetch_code.py ${BUCKET}
ExecStart=/opt/fhe/venv/bin/python cloud_server.py --port 8000 --bucket ${BUCKET} --publish-config
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable fhe
systemctl restart fhe
