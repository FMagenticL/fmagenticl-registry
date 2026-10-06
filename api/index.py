import sys
import os

# Add parent directory to sys.path so fmagenticl modules are resolvable by Vercel serverless
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fmagenticl.server.main import app

# Vercel looks for 'app' as the ASGI entry point
