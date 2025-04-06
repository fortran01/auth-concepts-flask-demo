from bs4 import BeautifulSoup

# Helper function to login a user
def login_user(client, username='admin', password='secret'):
    """Helper function to login a user"""
    return client.post('/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)

class TestCSRFDemo:
    """Tests for the CSRF vulnerability demo"""
    
    def test_csrf_demo_page(self, client):
        """Test that the CSRF demo page loads correctly"""
        response = client.get('/csrf-demo')
        assert response.status_code == 200
        assert b'Cross-Site Request Forgery (CSRF) Demo' in response.data
        assert b'What is CSRF?' in response.data
        assert b'How Does it Work?' in response.data
        assert b'Vulnerable Page' in response.data
        assert b'Protected Page' in response.data
        assert b'Malicious Site' in response.data
    
    def test_profile_page_requires_login(self, client):
        """Test that the profile page requires login"""
        # Try without login
        response = client.get('/profile', follow_redirects=True)
        assert response.status_code == 200
        assert b'Please log in to access this page' in response.data
        
        # Login and try again
        login_user(client)
        response = client.get('/profile')
        assert response.status_code == 200
        assert b'User Profile (Vulnerable to CSRF)' in response.data
    
    def test_profile_protected_page_requires_login(self, client):
        """Test that the protected profile page requires login"""
        # Try without login
        response = client.get('/profile-protected', follow_redirects=True)
        assert response.status_code == 200
        assert b'Please log in to access this page' in response.data
        
        # Login and try again
        login_user(client)
        response = client.get('/profile-protected')
        assert response.status_code == 200
        assert b'User Profile (Protected from CSRF)' in response.data
    
    def test_update_email_vulnerable(self, client):
        """Test updating email on the vulnerable page"""
        # Login first
        login_user(client)
        
        # Visit the profile page
        response = client.get('/profile')
        assert response.status_code == 200
        
        # Update the email
        response = client.post('/update-email', data={
            'email': 'new_email@example.com'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Email updated successfully!' in response.data
        assert b'new_email@example.com' in response.data
        
        # Check that the email was updated in the session
        with client.session_transaction() as sess:
            assert sess['email'] == 'new_email@example.com'
    
    def test_update_email_protected(self, client):
        """Test updating email on the protected page with CSRF token"""
        # Login first
        login_user(client)
        
        # Visit the protected profile page to get the CSRF token
        response = client.get('/profile-protected')
        assert response.status_code == 200
        
        # Extract the CSRF token from the page
        soup = BeautifulSoup(response.data, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
        assert csrf_token is not None
        
        # Update the email with the CSRF token
        response = client.post('/update-email-protected', data={
            'email': 'protected_email@example.com',
            'csrf_token': csrf_token
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Email updated successfully!' in response.data
        assert b'protected_email@example.com' in response.data
        
        # Check that the email was updated in the session
        with client.session_transaction() as sess:
            assert sess['email'] == 'protected_email@example.com'
    
    def test_update_email_protected_without_csrf_token(self, client):
        """Test that updating email fails without a CSRF token"""
        # Login first
        login_user(client)
        
        # Try to update the email without a CSRF token
        response = client.post('/update-email-protected', data={
            'email': 'hacked@example.com'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Invalid CSRF token' in response.data
        
        # Check that the email was not updated
        with client.session_transaction() as sess:
            assert sess.get('email') != 'hacked@example.com'
    
    def test_update_email_protected_with_invalid_csrf_token(self, client):
        """Test that updating email fails with an invalid CSRF token"""
        # Login first
        login_user(client)
        
        # Try to update the email with an invalid CSRF token
        response = client.post('/update-email-protected', data={
            'email': 'hacked@example.com',
            'csrf_token': 'invalid_token'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Invalid CSRF token' in response.data
        
        # Check that the email was not updated
        with client.session_transaction() as sess:
            assert sess.get('email') != 'hacked@example.com'
    
    def test_simulated_csrf_attack(self, client):
        """Test simulating a CSRF attack"""
        # Login first
        login_user(client)
        
        # Set initial email address
        client.post('/update-email', data={
            'email': 'initial@example.com'
        }, follow_redirects=True)
        
        # Check that the email was set correctly
        with client.session_transaction() as sess:
            assert sess['email'] == 'initial@example.com'
        
        # Simulate an attack by accessing the malicious site
        # We'll mimic what the malicious form would do by sending a POST directly
        response = client.post('/update-email', data={
            'email': 'hacked@malicious.com'
        }, follow_redirects=True)
        
        # The attack should succeed against the vulnerable endpoint
        assert response.status_code == 200
        with client.session_transaction() as sess:
            assert sess['email'] == 'hacked@malicious.com'
        
        # Now try the same attack against the protected endpoint
        client.post('/update-email-protected', data={
            'email': 'hacked_again@malicious.com'
        }, follow_redirects=True)
        
        # The attack should fail - email should not be updated
        with client.session_transaction() as sess:
            assert sess['email'] != 'hacked_again@malicious.com'
    
    def test_malicious_site_page(self, client):
        """Test that the malicious site page loads correctly"""
        response = client.get('/malicious-site')
        assert response.status_code == 200
        assert b'Malicious Site (Demo)' in response.data
        assert b'This page simulates a malicious website' in response.data
        
        # Check that the hidden form is present
        soup = BeautifulSoup(response.data, 'html.parser')
        form = soup.find('form', {'id': 'csrf-form'})
        assert form is not None
        assert form['action'].endswith('/update-email')
        assert form['method'].lower() == 'post'
        
        # Check that the email input is present with the malicious value
        email_input = form.find('input', {'name': 'email'})
        assert email_input is not None
        assert email_input['value'] == 'hacked@malicious.com'
        
        # Check that the JavaScript to auto-submit the form is present
        script = soup.find('script')
        script_text = script.string
        assert 'submit' in script_text
        assert 'csrf-form' in script_text 