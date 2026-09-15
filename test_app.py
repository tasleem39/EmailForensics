import app as app_module


def test_home_page_uses_static_background_asset():
    client = app_module.app.test_client()
    response = client.get('/')
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert '/static/email-bg.png' in html


def test_overview_page_renders_when_report_exists():
    client = app_module.app.test_client()
    app_module.app.config['LAST_REPORT'] = {
        'threat_assessment': {
            'fraud_score': 82,
            'verdict': 'High risk',
            'reasons': ['Suspicious sender behavior', 'Authentication failures']
        },
        'email_summary': {
            'from': 'ops@example.com',
            'to': 'analyst@example.com',
            'reply_to': 'noreply@example.com',
            'subject': 'Action required',
            'message_id': 'abc123',
            'body': 'Body text'
        }
    }
    app_module.app.config['LAST_FILENAME'] = 'sample.eml'

    response = client.get('/overview')
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'Threat Assessment' in html
    assert 'sample.eml' in html
