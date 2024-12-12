import subprocess
import sys

# Add logging for debugging
print("Starting script execution...")

# PowerShell command as a string, ensuring proper escaping of quotes
powershell_command = """
try {
    $policyName = "Enforce password history"
    $requiredValue = 24

    Write-Output "Checking registry path..."
    # Fetch the current value for "Enforce password history"
    $currentValue = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "EnforcePasswordHistory" -ErrorAction Stop).EnforcePasswordHistory

    Write-Output "Current value retrieved: $currentValue"

    # Set default status to "Fail"
    $status = "Fail"

    # Compare current value with required value
    if ($currentValue -ge $requiredValue) {
        $status = "Pass"
    }

    # Output the result in the specified format
    Write-Output "Check: $policyName"
    Write-Output "Status: $status"
    Write-Output "Current Value: $currentValue"
    Write-Output "Expected Value: $requiredValue or more"
    Write-Output "Recommendation: Set $policyName to 24 or more passwords"

    # Include remediation steps only if the check fails
    if ($status -eq "Fail") {
        Write-Output "Remediation: To configure this setting, follow these steps:"
        Write-Output "1. Open PowerShell with administrator privileges."
        Write-Output "2. Run the following command to set Enforce password history to 24 or more:"
        Write-Output "   Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnforcePasswordHistory' -Value 24"
    }
} catch {
    Write-Output "Error occurred: $_"
    exit 1
}
"""

print("Attempting to run PowerShell command...")

try:
    # Run the PowerShell command with subprocess.run() and capture output
    result = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-Command", powershell_command],
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE,
        text=True,
        check=True  # This will raise CalledProcessError if PowerShell returns non-zero
    )

    print("PowerShell command completed.")
    
    # Check for errors or output
    if result.stderr:
        print(f"Error: {result.stderr}")
    else:
        print("Output:")
        print(result.stdout)

except subprocess.CalledProcessError as e:
    print(f"PowerShell execution failed with return code {e.returncode}")
    print(f"Error output: {e.stderr}")
    print(f"Standard output: {e.stdout}")
except Exception as e:
    print(f"An unexpected error occurred: {str(e)}")
    print(f"Error type: {type(e)}")

print("Script execution completed.")
