#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal app startup for development mode
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)

def start_app():
    """Start the application in development mode"""
    try:
        print("🚀 Starting Jira Analyzer in Development Mode...")
        print("=" * 50)
        
        # Import and create app
        from app_config import create_app
        from app_core import register_routes
        
        print("📦 Creating application components...")
        app, security, limiter, jira_api, classifier, app_logger = create_app()
        
        print("🛣️  Registering routes...")
        register_routes(app, security, limiter, jira_api, classifier, app_logger)
        
        print("✅ Application ready!")
        print("🌐 URL: http://localhost:5001")
        print("👤 Admin Panel: http://localhost:5001/admin/login")
        print("📝 Debug Mode: ON")
        print("🔓 SSL: OFF")
        print("=" * 50)
        print("⏸️  Press Ctrl+C to stop")
        print("")
        
        # Start the server
        app.run(
            debug=True,
            host='127.0.0.1',
            port=5001,
            threaded=True,
            use_reloader=False  # Disable reloader to avoid double startup
        )
        
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(start_app())
