# Final-Year-Project
Setup in the AWS console

Use the same region everywhere. I suggest Asia Pacific (Singapore) ap-southeast-1, selected in the top-right corner.

1. Account
Sign up at aws.amazon.com/free. New customers get $100 in credits at sign-up and can earn $100 more by using services such as EC2. 
amazon
Choose the Free plan. It expires 6 months after sign-up or when the credits run out, whichever comes first. Delete everything when you finish the experiment. 
amazon
2. Create the S3 bucket
Open S3 → Create bucket.
Name: it must be globally unique, for example fhe-demo-yourname-123. Write it down.
Keep Block all public access ticked, then click Create bucket.
Open the bucket and choose Create folder twice: code and source.
Open code and use Upload to add common.py and cloud_server.py.
Open source and upload your three CSVs. Name them dataset1.csv, dataset2.csv and dataset3.csv, or match whatever names you use in the Control Room.
3. Give the server permission to use the bucket
Open IAM → Policies → Create policy → JSON tab.
Paste the content of iam_policy.json, replacing YOUR-BUCKET-NAME in both places with your bucket name.
Name the policy fhe-demo-s3 and create it.
Open IAM → Roles → Create role. For the trusted entity choose AWS service, use case EC2.
Tick two policies: fhe-demo-s3 and AmazonSSMManagedInstanceCore. The second lets you open a terminal in the browser without opening any SSH port.
Name the role fhe-demo-ec2-role and create it.
4. Launch the server
Open EC2 → Launch instance and set:
Name: fhe-server
OS image: Ubuntu → Ubuntu Server 24.04 LTS, 64-bit (x86).
Instance type: m7i-flex.large (2 vCPU, 8 GB). The Free plan allows a short list of types that includes C7i-flex.large and M7i-flex.large, while xlarge sizes and above weren’t available on it. Pick one marked “Free tier eligible” and avoid the ARM (t4g) types, since TenSEAL ships x86 builds. 8 GB is enough for three datasets. 
dev
classmethod
Key pair: choose Proceed without a key pair.
Network settings: click Edit, create a new security group named fhe-demo-sg, and delete the default SSH rule. Click Add security group rule and set Type Custom TCP, Port 8000, Source My IP.
Storage: 20 GiB.
Expand Advanced details and set IAM instance profile to fhe-demo-ec2-role.
In the User data box, paste ec2_user_data.sh after changing the BUCKET="YOUR-BUCKET-NAME" line to your bucket name.
Click Launch instance.
5. Get the keys

Wait about 4 minutes. Then open your bucket in S3. A config/ folder will appear containing demo_config.json. Its appearance means the server started correctly.

Download that file into your cloud_demo folder. Then:

Copy the instance’s Public IPv4 address from the EC2 instance page.
Open demo_config.json and set "server_url": "http://PUBLIC_IP:8000".
Also set pso_degree and pso_arity to your PSO result. The defaults are 16384 and 4.
6. Your demo computer

Run pip install -r requirements.txt and python launcher.py, then sign in on each window. (On Ubuntu, also run sudo apt install python3-tk first.) The suggested demo script from my earlier messages still applies.

Useful details
Updating the code: upload the new file to code/ in S3, then use Instance state → Reboot instance. The server downloads the newest code every time it starts.
Stopping the VM: Instance state → Stop saves money. When you start it again, the server starts by itself and the data persists in S3. The public IP will probably change, so update server_url.
If your IP changes: edit the security group’s inbound rule under fhe-demo-sg.
Showing evidence: in S3, open vault/dataset1/. The encrypted objects are there, and a tampered object’s Last modified time changes.
If something fails
Select the instance and choose Connect → Session Manager. This opens a terminal.
Run sudo journalctl -u fhe -n 30. A missing file in code/ or a wrong bucket name usually shows up here.
Clean up
Terminate the instance.
Delete the security group, the IAM role and the policy.
In S3, click Empty on the bucket, then Delete.

demo_config.json in the bucket contains the three access keys, so delete the bucket when finished.
