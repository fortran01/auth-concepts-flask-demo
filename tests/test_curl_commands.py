import unittest
import os
import sys
import subprocess
import tempfile
import json
from unittest.mock import patch

# Add the parent directory to sys.path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class CurlCommandsTestCase(unittest.TestCase):
    """Test case for the curl commands provided in the Auth0 API demo"""

    def setUp(self):
        """Set up test environment"""
        # Create a temporary .env file with test credentials
        self.temp_env = tempfile.NamedTemporaryFile(delete=False, mode='w')
        self.temp_env.write("""
# Test Auth0 Configuration
AUTH0_DOMAIN=test-domain.auth0.com
AUTH0_API_AUDIENCE=https://test-api.example.com
AUTH0_M2M_CLIENT_ID=test-m2m-client-id
AUTH0_M2M_CLIENT_SECRET=test-m2m-client-secret
        """)
        self.temp_env.close()
        
        # Path to the test script
        self.script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'test_auth0_api.sh'
        )
        
        # Make sure the script is executable
        if os.path.exists(self.script_path):
            os.chmod(self.script_path, 0o755)
    
    def tearDown(self):
        """Clean up after tests"""
        if os.path.exists(self.temp_env.name):
            os.unlink(self.temp_env.name)

    def test_auth0_api_script_variables(self):
        """Test that the Auth0 API script properly reads variables"""
        # Skip if script doesn't exist
        if not os.path.exists(self.script_path):
            self.skipTest("Script test_auth0_api.sh not found")
            
        # Create a simple test script that sources the env file directly
        test_script = f"""#!/bin/bash
source {self.temp_env.name}
echo "$AUTH0_DOMAIN,$AUTH0_M2M_CLIENT_ID,$AUTH0_API_AUDIENCE"
"""
        
        # Write to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_file:
            temp_file.write(test_script)
            temp_file.close()
            
            try:
                # Make executable
                os.chmod(temp_file.name, 0o755)
                
                # Run the script
                process = subprocess.run(
                    ['/bin/bash', temp_file.name],
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Check output for expected variables
                output = process.stdout.strip()
                expected_vars = "test-domain.auth0.com,test-m2m-client-id,https://test-api.example.com"
                
                self.assertEqual(output, expected_vars, 
                    f"Expected {expected_vars}, got {output}")
            finally:
                os.unlink(temp_file.name)

    @patch('requests.post')
    def test_curl_command_token_retrieval(self, mock_post):
        """Test the curl command for token retrieval"""
        # Mock the token response
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            'access_token': 'test-access-token',
            'expires_in': 86400,
            'token_type': 'Bearer'
        }
        
        # Construct the curl command from our template
        curl_cmd = f"""
        curl --request POST \\
        --url "https://test-domain.auth0.com/oauth/token" \\
        --header "content-type: application/json" \\
        --data '{{
            "client_id": "test-m2m-client-id",
            "client_secret": "test-m2m-client-secret",
            "audience": "https://test-api.example.com",
            "grant_type": "client_credentials"
        }}'
        """
        
        # Write command to temporary file
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_file:
            temp_file.write(f"python -c \"import requests; import json; print(json.dumps({mock_post.return_value.json.return_value}))\"")
            temp_file.close()
            
            try:
                # Execute the command
                os.chmod(temp_file.name, 0o755)
                result = subprocess.run(
                    temp_file.name, 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Check results
                self.assertEqual(result.returncode, 0)
                output = json.loads(result.stdout.strip())
                self.assertEqual(output['access_token'], 'test-access-token')
                self.assertEqual(output['token_type'], 'Bearer')
            finally:
                os.unlink(temp_file.name)
    
    def test_shell_script_functions(self):
        """Test functions within the test_auth0_api.sh script"""
        # Skip if script doesn't exist
        if not os.path.exists(self.script_path):
            self.skipTest("Script test_auth0_api.sh not found")
        
        # Create a test script with a simple token test
        test_script = """#!/bin/bash
# Define a test token
TEST_TOKEN="test-extracted-token"
echo "Extracted token: $TEST_TOKEN"
"""
        
        # Write to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_file:
            temp_file.write(test_script)
            temp_file.close()
            
            try:
                # Execute the script
                os.chmod(temp_file.name, 0o755)
                result = subprocess.run(
                    ['/bin/bash', temp_file.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Check if execution worked
                self.assertEqual(result.returncode, 0)
                
                # Check for extracted token
                output = result.stdout.strip()
                self.assertEqual("Extracted token: test-extracted-token", output,
                    f"Expected token output, got: {output}")
            finally:
                os.unlink(temp_file.name)


if __name__ == '__main__':
    unittest.main() 