from sqlalchemy import create_engine
import pandas as pd
import subprocess
import threading
import time
import datetime

connection_string = "mysql+pymysql://admin:RrAkNvmDOZAdIBdCKMupTqGGTLTWwyWT@auditguard.c5eq84gqy82t.eu-north-1.rds.amazonaws.com:3306/auditguard"
conn = create_engine(connection_string)

# Test connection
with conn.connect() as connection:
    print("Connection successful!")
    policy = pd.read_sql("""SELECT 
    c.title,
    c.description,
    c.cis_index,
    p.command,
    p.remediation,
    p.expected_value
    FROM 
        cis_benchmark c
    JOIN 
        policies p ON c.id = p.cis_benchmark_id
    JOIN 
        policy_os_mapping os ON os.policy_id = c.id
    WHERE os.os_type_id=1""",conn)
    policies = policy['command']
    

date = str(datetime.datetime.now())
with open('./audit_status.txt','w') as f:
            f.write(f"Audit Completed Status : {date}\n\n")

results = []
def powershell_command_exec(command, index):
    try:
        powershell_command = [
            'powershell',
            '-ExecutionPolicy',
            'Bypass',
            '-NoProfile',
            '-Command',
            command
        ]
        result = subprocess.run(powershell_command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            results.append((index, result.stdout))
        else:
            results.append((index, result.stderr))
    except Exception as e:
        print(f"Error executing command at index {index}: {e}")

threads = []
starttime = time.time()
for i,command in enumerate(policies):
    thread=threading.Thread(target=powershell_command_exec,args=(command,i,))
    threads.append(thread)
    thread.start()

for i in range(len(threads)):
    threads[i].join()

with open('./audit_status.txt','a') as f:
    for result in results:
        f.write(result[1]+"\n")
        f.write("-"*50+"\n")

print(len(results))
finishtime = time.time()
print("Task Completed")
print(finishtime-starttime)
