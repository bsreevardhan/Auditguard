from sqlalchemy import create_engine
import pandas as pd
import subprocess
import threading
import time
import datetime

connection_string = "mysql+pymysql://admin:RrAkNvmDOZAdIBdCKMupTqGGTLTWwyWT@database-1.cvw6wogyqzxu.us-east-1.rds.amazonaws.com:3306/auditguard"
conn = create_engine(connection_string)

level = input("Enter the level to run the redhat script: ")
level_split = level.split(',')

level_str = ','.join([f"'{l}'" for l in level_split])

# Test connection
with conn.connect() as connection:
    print("Connection successful!")
    policy = pd.read_sql(f"""
        SELECT
            c.title,
            c.description,
            c.cis_index,
            c.level,
            p.command,
            p.remediation,
            p.expected_value
        FROM
            cis_benchmark c
        JOIN
            policies p ON c.id = p.cis_benchmark_id
        JOIN
            policy_os_mapping os ON os.policy_id = c.id
        WHERE os.os_type_id=4 AND c.level IN ({level_str})
    """, conn)
    print(policy)
    policies = policy['command']

date = str(datetime.datetime.now())
with open('./audit_status.txt', 'w') as f:
    f.write(f"Audit Completed Status: {date}\n\n")

results = []

def powershell_command_exec(command, index):
    try:
        powershell_command = [
            'sudo', 'bash', '-c',
            command
        ]
        result = subprocess.run(powershell_command, capture_output=True, text=True)
        if result.returncode == 0:
            print(policy.iloc[index].cis_index, result.stdout + '\n\n')
            results.append({
                'cis_index': policy.iloc[index].cis_index,
                'title': policy.iloc[index].title,
                'status': 'Pass',
                'output': result.stdout
            })
        else:
            results.append({
                'cis_index': policy.iloc[index].cis_index,
                'title': policy.iloc[index].title,
                'status': 'Fail',
                'output': result.stderr
            })
    except Exception as e:
        print(f"Error executing command at index {index}: {e}")
        results.append({
            'cis_index': policy.iloc[index].cis_index,
            'title': policy.iloc[index].title,
            'status': 'Error',
            'output': str(e)
        })

threads = []
starttime = time.time()
for i, command in enumerate(policies):
    thread = threading.Thread(target=powershell_command_exec, args=(command, i,))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

pass_count = 0
fail_count = 0

with open('./audit_status_redhat.txt', 'a') as f:
    for result in results:
        f.write(f"{result['cis_index']} {result['title']}\n\n")
        f.write(f"Status: {result['status']}\n")
        if "pass" in result['status'].lower():
            pass_count+=1
        else:
            fail_count+=1
        f.write(result['output'] + "\n")
        f.write("-" * 50 + "\n")

# Save results to CSV
output_csv = f'./audit_results_redhat9_{str(datetime.datetime.now())}.csv'
df_results = pd.DataFrame(results)
df_results.to_csv(output_csv, index=False)
print(f"Results saved to {output_csv}")

print("Pass Count : ",pass_count)
print("Fail Count : ",fail_count)
print("Compilance score: ",(pass_count/fail_count)*100)

print(len(results))
finishtime = time.time()
print("Task Completed")
print(f"Execution Time: {finishtime - starttime:.2f} seconds")