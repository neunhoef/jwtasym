#!/bin/bash
# Example usage script for jwt-ps256 tool

echo "=== JWT PS256 Tool Examples ==="
echo ""

# Example 1: Generate keypair
echo "1. Generate RSA keypair:"
echo "   ./jwt-ps256 keygen"
echo ""

# Example 2: Create a simple token
echo "2. Create a JWT token for user 'alice' valid for 1 hour (3600 seconds):"
echo "   ./jwt-ps256 create --username alice --expiry 3600"
echo ""

# Example 3: Create token with additional claims
echo "3. Create a token with additional claims:"
echo "   ./jwt-ps256 create --username bob --expiry 7200 --claims '{\"role\":\"admin\",\"email\":\"bob@example.com\"}'"
echo ""

# Example 4: Verify a token
echo "4. Verify a token:"
echo "   ./jwt-ps256 verify eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZSIsImlhdCI6MTY0MDk5NTIwMCwiZXhwIjoxNjQwOTk4ODAwfQ.signature..."
echo ""

# Example 5: Complete workflow
echo "5. Complete workflow:"
echo "   # Generate keys"
echo "   ./jwt-ps256 keygen"
echo ""
echo "   # Create token and save to variable"
echo "   TOKEN=\$(./jwt-ps256 create --username developer --expiry 86400 | tail -1)"
echo ""
echo "   # Verify the token"
echo "   ./jwt-ps256 verify \"\$TOKEN\""
echo ""

# Example 6: Custom key paths
echo "6. Using custom key paths:"
echo "   ./jwt-ps256 keygen --private-key keys/private.pem --public-key keys/public.pem"
echo "   ./jwt-ps256 create --username test --expiry 1800 --private-key keys/private.pem"
echo "   ./jwt-ps256 verify \"\$TOKEN\" --public-key keys/public.pem"
echo ""

# Example 7: Larger key size
echo "7. Generate 4096-bit keypair:"
echo "   ./jwt-ps256 keygen --bits 4096"
