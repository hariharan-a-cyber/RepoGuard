# SAFE: obvious test fixture, not a real secret
def test_login():
    fake_password = "test_password_placeholder_value"
    assert authenticate("user", fake_password) is not None
