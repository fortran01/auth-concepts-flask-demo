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
        assert b'Malicious Site Demonstrations' in response.data
        assert b'Attack on Vulnerable Page' in response.data
        assert b'Attack on Protected Page' in response.data
    
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
        assert b'Update Email Address' in response.data
        assert b'Update Username' in response.data
    
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
        assert b'Update Email Address' in response.data
        assert b'Update Username' in response.data
    
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
    
    def test_update_username_vulnerable(self, client):
        """Test updating username on the vulnerable page"""
        # Login first
        login_user(client)
        
        # Visit the profile page
        response = client.get('/profile')
        assert response.status_code == 200
        
        # Update the username
        response = client.post('/update-username', data={
            'username': 'new_username'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Username updated successfully!' in response.data
        assert b'new_username' in response.data
        
        # Check that the username was updated in the session
        with client.session_transaction() as sess:
            assert sess['username'] == 'new_username'
    
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
    
    def test_update_username_protected(self, client):
        """Test updating username on the protected page with CSRF token"""
        # Login first
        login_user(client)
        
        # Visit the protected profile page to get the CSRF token
        response = client.get('/profile-protected')
        assert response.status_code == 200
        
        # Extract the CSRF token from the page
        soup = BeautifulSoup(response.data, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
        assert csrf_token is not None
        
        # Update the username with the CSRF token
        response = client.post('/update-username-protected', data={
            'username': 'protected_username',
            'csrf_token': csrf_token
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Username updated successfully!' in response.data
        assert b'protected_username' in response.data
        
        # Check that the username was updated in the session
        with client.session_transaction() as sess:
            assert sess['username'] == 'protected_username'
    
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
    
    def test_update_username_protected_without_csrf_token(self, client):
        """Test that updating username fails without a CSRF token and sets attack flag"""
        # Login first
        login_user(client)
        
        # Set initial username
        with client.session_transaction() as sess:
            sess['username'] = 'original_username'
        
        # Try to update the username without a CSRF token
        response = client.post('/update-username-protected', data={
            'username': 'hacked_username'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Invalid CSRF token' in response.data
        assert b'Attack Detected!' in response.data
        
        # Check that the username was not updated and attack was detected
        with client.session_transaction() as sess:
            assert sess.get('username') == 'original_username'
            # Attack flag should be cleared after being displayed
            assert sess.get('csrf_attack_attempted') is None
    
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
    
    def test_update_username_protected_with_invalid_csrf_token(self, client):
        """Test that updating username fails with an invalid CSRF token and sets attack flag"""
        # Login first
        login_user(client)
        
        # Set initial username
        with client.session_transaction() as sess:
            sess['username'] = 'original_username'
        
        # Try to update the username with an invalid CSRF token
        response = client.post('/update-username-protected', data={
            'username': 'hacked_username',
            'csrf_token': 'invalid_token'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Invalid CSRF token' in response.data
        assert b'Attack Detected!' in response.data
        
        # Check that the username was not updated and attack was detected
        with client.session_transaction() as sess:
            assert sess.get('username') == 'original_username'
            # Attack flag should be cleared after being displayed
            assert sess.get('csrf_attack_attempted') is None
    
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
        # Mimic what the malicious form would do by sending a POST directly
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
    
    def test_simulated_csrf_attack_on_username(self, client):
        """Test simulating a CSRF attack on the username field"""
        # Login first
        login_user(client)
        
        # Set initial username
        client.post('/update-username', data={
            'username': 'initial_username'
        }, follow_redirects=True)
        
        # Check that the username was set correctly
        with client.session_transaction() as sess:
            assert sess['username'] == 'initial_username'
        
        # Simulate an attack by accessing the malicious site
        # Mimic what the malicious form would do by sending a POST directly
        response = client.post('/update-username', data={
            'username': 'hacked_username'
        }, follow_redirects=True)
        
        # The attack should succeed against the vulnerable endpoint
        assert response.status_code == 200
        with client.session_transaction() as sess:
            assert sess['username'] == 'hacked_username'
        
        # Now try the same attack against the protected endpoint
        response = client.post('/update-username-protected', data={
            'username': 'hacked_again_username'
        }, follow_redirects=True)
        
        # The attack should fail - username should not be updated
        assert b'Attack Detected!' in response.data
        with client.session_transaction() as sess:
            assert sess['username'] != 'hacked_again_username'
    
    def test_malicious_site_page(self, client):
        """Test that the malicious site page loads correctly"""
        response = client.get('/malicious-site')
        assert response.status_code == 200
        assert b'Malicious Site (Demo)' in response.data
        assert b'This page simulates a malicious website' in response.data
        
        # Check that the vulnerable target option is active
        target_text = 'targets the <strong>vulnerable profile page</strong>'
        assert target_text.encode() in response.data
        
        # Check that the hidden form is present
        soup = BeautifulSoup(response.data, 'html.parser')
        form = soup.find('form', {'id': 'csrf-attack-form'})
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
        assert 'csrf-attack-form' in script_text
    
    def test_malicious_site_protected_page(self, client):
        """Test that the malicious site targeting protected page loads correctly"""
        response = client.get('/malicious-site-protected')
        assert response.status_code == 200
        assert b'Malicious Site (Demo)' in response.data
        assert b'This page simulates a malicious website' in response.data
        
        # Check that the protected target option is active
        msg = 'targets the <strong>protected profile page</strong>'
        assert msg.encode() in response.data
        
        # Check that the hidden form is present
        soup = BeautifulSoup(response.data, 'html.parser')
        form = soup.find('form', {'id': 'csrf-attack-form'})
        assert form is not None
        assert form['action'].endswith('/update-username-protected')
        assert form['method'].lower() == 'post'
        
        # Check that the username input is present with the malicious value
        username_input = form.find('input', {'name': 'username'})
        assert username_input is not None
        assert username_input['value'] == 'hacked_username'
        
        # Check that there is NO CSRF token in the form
        csrf_input = form.find('input', {'name': 'csrf_token'})
        assert csrf_input is None
        
        # Check that the JavaScript to auto-submit the form is present
        script = soup.find('script')
        script_text = script.string
        assert 'submit' in script_text
        assert 'csrf-attack-form' in script_text 