from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view
import platform, subprocess, re
import threading, time, datetime
import pandas as pd
from sqlalchemy import create_engine
from django.conf import settings
import os ,socket
from .models import (UserSystemConfig,AuditResult,GroupList,GroupPolicy)
import concurrent.futures
from .serializers import GroupListSerializer, GroupPolicySerializer, GroupListDetailSerializer

@api_view(["GET"])
def get_os_system(request):
    try:
        # Try to get existing system config
        data = UserSystemConfig.objects.get(pk=1)
        system_info = {
            "os_name": data.os_name,
            "os_version": data.os_version,
            "os_config": data.os_config,
            "architecture": data.architecture,
            "hostname": data.hostname,
            "ip_address": data.ip_address,
            "audit_results_path": data.audit_results_path,
        }
    except UserSystemConfig.DoesNotExist:
        # Get detailed OS information
        os_type = platform.system()
        os_name = ""
        os_version = ""
        os_config = ""

        if os_type == "Windows":
            try:
                # Run systeminfo command and capture output
                result = subprocess.run(['systeminfo'], capture_output=True, text=True)
                output = result.stdout.split('\n')
                
                for line in output:
                    if "OS Name:" in line:
                        os_name = line.split(':')[1].strip()
                    elif "OS Version:" in line:
                        os_version = line.split(':')[1].strip()
                    elif "OS Configuration:" in line:
                        os_config = line.split(':')[1].strip()
            except Exception as e:
                os_name = f"Windows {platform.release()}"
                os_version = platform.version()
                os_config = "Unknown"

        elif os_type == "Linux":
            try:
                # Run hostnamectl command and capture output
                result = subprocess.run(['hostnamectl'], capture_output=True, text=True)
                output = result.stdout.split('\n')
                
                for line in output:
                    if "Operating System:" in line:
                        os_name = line.split(':')[1].strip()
                    elif "Kernel:" in line:
                        os_version = line.split(':')[1].strip()
                    elif "Deployment:" in line:
                        os_config = line.split(':')[1].strip()
                
                if not os_config:
                    os_config = "Server" if "server" in os_name.lower() else "Desktop"
            except Exception as e:
                os_name = f"Linux {platform.release()}"
                os_version = platform.version()
                os_config = "Unknown"
        else:
            os_name = f"{os_type} {platform.release()}"
            os_version = platform.version()
            os_config = "Unknown"

        # Determine appropriate audit results path based on OS
        if os_type == "Windows":
            base_path = os.path.join(os.path.expanduser("~"), "audit_results")
        else:
            base_path = os.path.join(os.path.expanduser("~"), ".audit_results")

        # Create directory if it doesn't exist
        try:
            os.makedirs(base_path, exist_ok=True)
        except OSError as e:
            return Response(
                {"error": f"Failed to create audit results directory: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Get os_index
        conn = create_engine(settings.CONNECTION_STRING)
        with conn.connect() as connection:
            operating_systems = pd.read_sql("SELECT * FROM operating_systems ORDER BY id", connection)
            os_index = get_os_index(operating_systems, {
                'os_name': os_name,
                'os_config': os_config
            })

        system_info = {
            "os_name": os_name,
            "os_version": os_version,
            "os_config": os_config,
            "architecture": platform.architecture()[0],
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "audit_results_path": base_path,
            "os_index": os_index,
        }
        UserSystemConfig.objects.create(**system_info)

    return Response(
        {"message": "System info retrieved successfully", "data": system_info},
        status=status.HTTP_200_OK
    )

    
@api_view(["GET"])
def run_script(request, *args, **kwargs):
    level = request.query_params.get('level', None)
    group = request.query_params.get('group', None)
    
    if not level and not group:
        return Response({"error": "Level or Group parameter is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Get current system configuration
        system_config = UserSystemConfig.objects.get(pk=1)
        
        if system_config.os_index == -1:
            return Response(
                {"error": "No matching OS configuration found. Please run system detection first."},
                status=status.HTTP_404_NOT_FOUND
            )

        conn = create_engine(settings.CONNECTION_STRING)
        results = []
        
        with conn.connect() as connection:
            if group:
                policy = get_os_policy(system_config.os_index, connection, group=group)
            else:
                level_list = level.split(',')
                policy = get_os_policy(system_config.os_index, connection, level=level_list)
            
            if policy.empty:
                return Response({"error": "No policies found"}, status=status.HTTP_404_NOT_FOUND)

            # Prepare script base command once
            os_name = platform.system()
            script_base = (
                ["powershell","-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
                if os_name == "Windows"
                else ["sudo","bash", "-c"]
                if os_name == "Linux"
                else None
            )
            
            if script_base is None:
                return Response({"error": "Unsupported operating system"}, status=status.HTTP_400_BAD_REQUEST)

            # Use ThreadPoolExecutor for better thread management
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(policy))) as executor:
                # Submit all tasks
                future_to_policy = {
                    executor.submit(
                        script_runner,
                        script_base.copy(),
                        row['command'],
                        row[['id', 'cis_index', 'title']].to_dict()
                    ): row for _, row in policy.iterrows()
                }
                
                # Collect results as they complete
                for future in concurrent.futures.as_completed(future_to_policy):
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception as e:
                        policy_row = future_to_policy[future]
                        results.append({
                            'policy_data': policy_row[['id', 'cis_index', 'title']].to_dict(),
                            'checked_status': {
                                'status': 'Error',
                                'error_message': str(e)
                            }
                        })

            if not results:
                return Response({"error": "No results were generated"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Generate audit date and CSV
            audit_date = str(datetime.datetime.now())
            try:
                csv_path = generate_audit_csv(results, audit_date, system_config, policy)
                
                # Use list comprehension for faster counting
                pass_count = sum(1 for result in results if result['checked_status']['status'].lower() == 'pass')
                total_count = len(results)
                fail_count = total_count - pass_count
                compliance_percentage = (pass_count / total_count) * 100 if total_count else 0

                # Create AuditResult entry
                audit_result = AuditResult.objects.create(
                    csv_file_location=csv_path,
                    pass_policy_count=pass_count,
                    fail_policy_count=fail_count,
                    compliance_percentage=compliance_percentage
                )

                return Response({
                    "result": results,
                    "date": audit_date,
                    "csv_file": csv_path,
                    "audit_result": {
                        "id": audit_result.id,
                        "pass_policy_count": audit_result.pass_policy_count,
                        "fail_policy_count": audit_result.fail_policy_count,
                        "compliance_percentage": audit_result.compliance_percentage,
                        "timestamp": audit_result.timestamp
                    }
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                return Response({
                    "result": results,
                    "date": audit_date,
                    "error": f"Failed to generate CSV: {str(e)}"
                }, status=status.HTTP_200_OK)
                
    except Exception as e:
        return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Modified script_runner function
def script_runner(script_base, command, policy_data):
    try:
        script = script_base + [command]
        result = subprocess.run(
            script,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout=stderr=None
        if result.returncode == 0:
            stdout=result.stdout
        else:
            stderr = result.stderr
        return {
            'policy_data': policy_data,
            'checked_status': (
                parse_data(stdout)
                if stdout
                else {
                    'status': 'Error',
                    'error_message': stderr
                }
            )
        }
    except subprocess.TimeoutExpired:
        return {
            'policy_data': policy_data,
            'checked_status': {
                'status': 'Error',
                'error_message': 'Command execution timed out'
            }
        }
    except Exception as e:
        return {
            'policy_data': policy_data,
            'checked_status': {
                'status': 'Error',
                'error_message': str(e)
            }
        }

#function to get the policy according to the operating system index
def get_os_policy(os_index, connection, id=None, level=None, group=None):
    """
    Get policies based on os_index and filters (id, level, or group)
    """
    if id is not None:
        policy = pd.read_sql(f'''
            SELECT 
                c.id,
                c.cis_index,
                c.title,
                c.description,
                c.level,
                c.version,
                pc.expected_value,
                pc.remediation
            FROM cis_benchmark c
            JOIN policy_os_mapping p ON p.policy_id = c.id 
            JOIN policies pc ON pc.cis_benchmark_id = c.id 
            WHERE p.os_type_id = {os_index} AND c.id = {id};
        ''', connection)
    elif level is not None:
        level_str = ','.join([f"'{l}'" for l in level])
        policy = pd.read_sql(f'''
            SELECT 
                c.id,
                c.title,
                c.cis_index,
                c.description,
                c.level,
                pc.command,
                pc.remediation,
                pc.expected_value
            FROM cis_benchmark c
            JOIN policy_os_mapping p ON p.policy_id = c.id
            JOIN policies pc ON pc.cis_benchmark_id = c.id
            WHERE p.os_type_id = {os_index} 
            AND c.level IN ({level_str});
        ''', connection)
    elif group is not None:
        # Get policies from group
        group_policies = GroupPolicy.objects.filter(group_id=group).values_list('policy_id', flat=True)
        if not group_policies:
            return pd.DataFrame()  # Return empty DataFrame if no policies found
        
        policy_ids = ','.join(map(str, group_policies))
        policy = pd.read_sql(f'''
            SELECT 
                c.id,
                c.title,
                c.cis_index,
                c.description,
                c.level,
                pc.command,
                pc.remediation,
                pc.expected_value
            FROM cis_benchmark c
            JOIN policy_os_mapping p ON p.policy_id = c.id
            JOIN policies pc ON pc.cis_benchmark_id = c.id
            WHERE p.os_type_id = {os_index} 
            AND c.id IN ({policy_ids});
        ''', connection)
    
    return policy

#function to get the operating system index    
def get_os_index(os_data, system_info):
    os_name = system_info['os_name']
    os_config = system_info['os_config']

    # Handle Windows matching
    if "Windows" in os_name:
        windows_version = "Windows " + os_name.split("Windows")[1].split()[0]  # Get Windows version number
        config_type = "Enterprise" if "Enterprise" in os_config else "Standalone"
        search_term = f"{windows_version} {config_type}"
    # Handle Ubuntu matching
    elif "Ubuntu" in os_name:
        ubuntu_version = os_name.split("Ubuntu")[1].strip()
        config_type = "Server" if "Server" in os_config else ""
        search_term = f"Ubuntu{' Server' if config_type == 'Server' else ''} {ubuntu_version}"
    # Handle Red Hat matching
    elif "Red Hat" in os_name:
        rhel_version = os_name.split("Red Hat Enterprise")[1].strip()
        search_term = f"Red Hat Enterprise {rhel_version}"
    else:
        return -1

    # Find matching OS configuration
    for i in range(len(os_data)):
        if os_data.iloc[i].os_name.lower() == search_term.lower():
            return os_data.iloc[i].id
    return -1

#api endpoint to get the policies of the particular os 
@api_view(['GET'])
def get_policy(request, *args, **kwargs):
    level = request.query_params.get('level', None)
    group = request.query_params.get('group', None)
    
    if not level and not group:
        return Response({"error": "Level or Group parameter is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Get current system configuration
        system_config = UserSystemConfig.objects.get(pk=1)
        
        if system_config.os_index == -1:
            return Response(
                {"error": "No matching OS configuration found. Please run system detection first."},
                status=status.HTTP_404_NOT_FOUND
            )
        
        conn = create_engine(settings.CONNECTION_STRING)
        with conn.connect() as connection:
            if group:
                policy = get_os_policy(system_config.os_index, connection, group=group)
            else:
                level_list = level.split(',')
                policy = get_os_policy(system_config.os_index, connection, level=level_list)
            
            if policy.empty:
                return Response({"error": "No policies found"}, status=status.HTTP_404_NOT_FOUND)
                
            return Response({"policies": policy}, status=status.HTTP_200_OK)
            
    except UserSystemConfig.DoesNotExist:
        return Response(
            {"error": "System configuration not found. Please run system detection first."},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#function to parse the result of the policy that are executed!
def parse_data(text):
    checked_data = {}
    # Extracting Status
    pattern = r"Status: (\w+)"
    status = re.search(pattern, text)
    if status:
        checked_data['status'] = status.group(1)
    
    # Extracting Current Value
    pattern = r"Current Value: (.+)"
    current_value = re.search(pattern, text)
    if current_value:
        checked_data['current_value'] = current_value.group(1)
    else:
        checked_data['current_value'] = None

    return checked_data

@api_view(['GET'])
def get_specific_policy(request, *args, **kwargs):
    try:
        system_config = UserSystemConfig.objects.get(pk=1)
        id = request.query_params.get('id', None)
        
        if not id:
            return Response({"error": "ID parameter is required"}, status=status.HTTP_400_BAD_REQUEST)
            
        if system_config.os_index == -1:
            return Response(
                {"error": "No matching OS configuration found. Please run system detection first."},
                status=status.HTTP_404_NOT_FOUND
            )
            
        conn = create_engine(settings.CONNECTION_STRING)
        with conn.connect() as connection:
            policy = get_os_policy(system_config.os_index, connection, id=id)
            if policy is None:
                return Response({"error": "There is no policy for the corresponding id!"}, status=status.HTTP_404_NOT_FOUND)
        
        return Response({"policy": policy}, status=status.HTTP_200_OK)
        
    except UserSystemConfig.DoesNotExist:
        return Response(
            {"error": "System configuration not found. Please run system detection first."},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def generate_audit_csv(results, audit_date, system_info, policy):
    try:
        # Create filename with timestamp
        timestamp = datetime.datetime.strptime(audit_date, '%Y-%m-%d %H:%M:%S.%f').strftime('%Y%m%d_%H%M%S')
        filename = f"audit_results_{timestamp}.csv"
        filepath = os.path.join(system_info.audit_results_path, filename)

        # Prepare data for CSV
        csv_data = []
        for result in results:
            policy_data = result.get('policy_data', {})
            check_status = result.get('checked_status', {})
            
            # Find matching policy row safely
            policy_row = policy[policy['id'] == policy_data.get('id', 0)]
            if policy_row.empty:
                continue
                
            row = {
                'Hostname': system_info.hostname,
                'Operating System': system_info.os_name,
                'Audit Date': audit_date,
                'CIS Index': policy_data.get('cis_index', ''),
                'Policy Title': policy_data.get('title', ''),
                'Level': policy_row.iloc[0].get('level', ''),
                'Description': policy_row.iloc[0].get('description', ''),
                'Status': check_status.get('status', 'Unknown'),
                'Current Value': check_status.get('current_value', 'N/A'),
                'Expected Value': policy_row.iloc[0].get('expected_value', ''),
                'Remediation': policy_row.iloc[0].get('remediation', '') if check_status.get('status', '').lower() == 'fail' else ''
            }
            csv_data.append(row)

        if not csv_data:
            raise Exception("No data to write to CSV")

        # Write to CSV
        df = pd.DataFrame(csv_data)
        df.to_csv(filepath, index=False)
        return filepath

    except Exception as e:
        raise Exception(f"Failed to generate CSV file: {str(e)}")
    

@api_view(['GET'])
def get_audit_results(request):
    try:
        # Get all audit results ordered by timestamp (most recent first, due to Meta ordering)
        audit_results = AuditResult.objects.all()
        
        # Convert audit results to list of dictionaries
        results = []
        for audit in audit_results:
            results.append({
                "id": audit.id,
                "csv_file_location": audit.csv_file_location,
                "pdf_file_location": audit.pdf_file_location,
                "pass_policy_count": audit.pass_policy_count,
                "fail_policy_count": audit.fail_policy_count,
                "compliance_percentage": audit.compliance_percentage,
                "timestamp": audit.timestamp,
                "total_policies": audit.pass_policy_count + audit.fail_policy_count
            })
        
        return Response({
            "count": len(results),
            "results": results
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {"error": f"Failed to retrieve audit results: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
def create_group(request, *args, **kwargs):
    try:
        # Get data from request
        group_data = {
            'group_name': request.data.get('group_name'),
            'level': request.data.get('level', '').upper()  # Convert to uppercase
        }
        
        # Validate level format
        valid_levels = ["L1", "L2", "BL", "CUSTOM"]
        if group_data['level'] not in valid_levels:
            return Response(
                {
                    "error": "Invalid level",
                    "details": {
                        "level": [f"Level must be one of: {', '.join(valid_levels)}"]
                    }
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        policies = request.data.get('policies', [])  # List of policy IDs

        # Validate and create group
        group_serializer = GroupListSerializer(data=group_data)
        if not group_serializer.is_valid():
            return Response(
                {"error": "Invalid group data", "details": group_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Save the group
        group = group_serializer.save()

        # Add policies to group
        policy_errors = []
        added_policies = []
        
        for policy_id in policies:
            policy_data = {
                'group': group.id,  # Changed from group_id to group
                'policy_id': policy_id
            }
            
            policy_serializer = GroupPolicySerializer(data=policy_data)
            if policy_serializer.is_valid():
                policy_serializer.save()
                added_policies.append(policy_id)
            else:
                policy_errors.append({
                    'policy_id': policy_id,
                    'errors': policy_serializer.errors
                })

        # Prepare response using the detail serializer
        detail_serializer = GroupListDetailSerializer(group)
        response_data = detail_serializer.data
        
        # Include errors if any occurred
        if policy_errors:
            response_data['policy_errors'] = policy_errors

        return Response(
            response_data,
            status=status.HTTP_201_CREATED if not policy_errors else status.HTTP_207_MULTI_STATUS
        )

    except Exception as e:
        # If any error occurs during group creation, delete the group if it was created
        if 'group' in locals():
            group.delete()
        
        return Response(
            {"error": f"Failed to create group: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


