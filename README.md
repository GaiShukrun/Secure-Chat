# Secure Chat Implementation

A secure chat implementation demonstrating RSA, Diffie-Hellman key exchange, and AES encryption with MongoDB storage for cryptographic keys.

## Components

- `server.py` - Alice's server implementation
- `client.py` - Bob's client implementation
- `crypto_participant.py` - Core cryptographic operations class
- `aes.py` - Custom AES-128 implementation
- `mongo_storage.py` - MongoDB interface for storing cryptographic keys

## Features

- RSA key generation and exchange
- Diffie-Hellman key exchange
- AES-128 encryption in CBC mode
- MongoDB storage of DH private keys
- Real-time secure chat between two participants

## Requirements

```bash
pip install pymongo
```

## Database Setup

The application uses MongoDB Atlas. Add your connection string in the code.


## How to Run

1. Start Alice's server first:
```bash
python server.py
```

2. In a different terminal, start Bob's client:
```bash
python client.py
```

3. The applications will:
   - Generate and exchange RSA keys
   - Perform Diffie-Hellman key exchange
   - Store DH private keys in MongoDB
   - Establish a secure AES-encrypted chat channel

4. To chat:
   - Type messages in either terminal
   - Type 'quit' to exit

## Protocol Flow

1. **RSA Setup**
   - Each participant generates RSA key pair
   - Public keys are exchanged

2. **Diffie-Hellman Exchange**
   - Alice sends DH parameters (g=5, p=2357)
   - Both parties generate private keys
   - Private keys are stored in MongoDB
   - Public values are exchanged (encrypted with RSA)

3. **AES Chat**
   - Shared secret is computed
   - AES-128 CBC mode encryption begins
   - Messages are encrypted before transmission

## Database Structure

DH keys are stored in the following format:
```json
{
    "participant": "Alice/Bob",
    "dh_private_key": "<secret_exponent>",
    "dh_public_key": "<calculated_value>",
    "base": 5,
    "modulus": 2357,
    "timestamp": "<ISODate>"
}
```

## Security Notes

- This is an educational implementation
- Uses fixed DH parameters for simplicity
- MongoDB stores sensitive keys (for demonstration)
- In production, would need additional security measures

## Troubleshooting

1. If port 5000 is in use:
   - Modify the port number in both server.py and client.py

2. If MongoDB connection fails:
   - Check your internet connection
   - Verify MongoDB Atlas is accessible

3. If chat disconnects:
   - Restart both server and client
   - Ensure both applications are running


   
