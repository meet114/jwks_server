#!/bin/bash
# Start the JWKS server with encryption key from environment

# Set encryption key (change this for production!)
export NOT_MY_KEY="my-secret-encryption-key-do-not-commit"

# Start the server
echo "Starting JWKS server on http://localhost:8000"
echo "Encryption key is set from NOT_MY_KEY environment variable"
echo ""
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
