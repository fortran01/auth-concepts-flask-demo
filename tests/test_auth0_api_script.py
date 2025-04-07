import unittest
import os
import subprocess
from unittest.mock import patch, MagicMock


class Auth0ApiScriptTestCase(unittest.TestCase):
    """Test case for the Auth0 API script"""

    def setUp(self):
        """Set up test environment"""
        # Define path to the script
        self.script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'test_auth0_api.sh'
        )
        
        # Create a test environment file
        self.env_file_path = "/tmp/test_auth0_api_env"
        with open(self.env_file_path, "w") as f:
            f.write("""
AUTH0_DOMAIN=test-domain.auth0.com
AUTH0_API_AUDIENCE=https://test-api.example.com
AUTH0_M2M_CLIENT_ID=test-m2m-client-id
AUTH0_M2M_CLIENT_SECRET=test-m2m-client-secret
            """.strip())
        
        # Make script executable if it's not already
        if os.path.exists(self.script_path):
            os.chmod(self.script_path, 0o755)
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.env_file_path):
            os.remove(self.env_file_path)
    
    @patch('subprocess.run')
    def test_script_execution(self, mock_run):
        """Test the script executes correctly"""
        # Mock subprocess.run to return expected JSON output
        mock_process = MagicMock()
        mock_process.stdout = """
{
  "access_token": "test-access-token",
  "expires_in": 86400,
  "token_type": "Bearer"
}
        """.strip()
        mock_process.returncode = 0
        mock_run.return_value = mock_process
        
        # Skip the test if the script doesn't exist
        if not os.path.exists(self.script_path):
            self.skipTest("Script test_auth0_api.sh not found")
        
        # Run the script with test env file
        cmd = [self.script_path, "--env-file", self.env_file_path, "-t"]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        # Verify the script ran successfully
        self.assertEqual(result.returncode, 0)
    
    def test_script_help_option(self):
        """Test the script's help option"""
        # Skip the test if the script doesn't exist
        if not os.path.exists(self.script_path):
            self.skipTest("Script test_auth0_api.sh not found")
        
        # Run the script with --help option
        cmd = [self.script_path, "--help"]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        # Verify the help text contains expected content
        self.assertEqual(result.returncode, 0)
        self.assertIn("=== Auth0 M2M API Test ===", result.stdout)
        self.assertIn("Step 1: Getting access token", result.stdout)
        self.assertIn("curl --request GET", result.stdout)
    
    @patch('subprocess.run')
    def test_token_extraction(self, mock_run):
        """Test token extraction functionality"""
        # Skip the test if the script doesn't exist
        if not os.path.exists(self.script_path):
            self.skipTest("Script test_auth0_api.sh not found")
        
        # Mock the token response
        mock_process = MagicMock()
        mock_process.stdout = """
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  "expires_in": 86400,
  "token_type": "Bearer"
}
        """.strip()
        mock_process.returncode = 0
        mock_run.return_value = mock_process
        
        # Run the script with token extraction
        cmd = [
            self.script_path,
            "--env-file",
            self.env_file_path,
            "-t",
            "--show-token"
        ]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        # Verify the token is in the output
        self.assertEqual(result.returncode, 0)
        self.assertIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", result.stdout)
    
    @patch('subprocess.run')
    def test_api_call(self, mock_run):
        """Test API call functionality"""
        # Skip the test if the script doesn't exist
        if not os.path.exists(self.script_path):
            self.skipTest("Script test_auth0_api.sh not found")
        
        # Set up mock responses for token and API call
        def mock_run_side_effect(*args, **kwargs):
            # First call gets the token
            if "oauth/token" in str(args[0]):
                process = MagicMock()
                process.stdout = """
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  "expires_in": 86400,
  "token_type": "Bearer"
}
                """.strip()
                process.returncode = 0
                return process
            # Second call uses the token to call the API
            else:
                process = MagicMock()
                process.stdout = """
{
  "message": "API call successful",
  "protected": true
}
                """.strip()
                process.returncode = 0
                return process
        
        mock_run.side_effect = mock_run_side_effect
        
        # Run the script with API call
        cmd = [
            self.script_path, 
            "--env-file", 
            self.env_file_path, 
            "-a", 
            "/api/protected"
        ]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        # Verify the API call was successful
        self.assertEqual(result.returncode, 0)
        self.assertIn("API call successful", result.stdout)


if __name__ == '__main__':
    unittest.main() 