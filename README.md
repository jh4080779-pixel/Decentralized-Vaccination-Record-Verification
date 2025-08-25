# 💉 Decentralized Vaccination Record Verification

Welcome to a secure, blockchain-powered solution for managing and verifying vaccination records! This project uses the Stacks blockchain and Clarity smart contracts to create decentralized identities (DIDs) tied to verifiable vaccination credentials. It addresses real-world challenges like fraudulent records, privacy concerns, cross-border verification delays, and centralized data vulnerabilities during pandemics or international travel.

## ✨ Features
🔒 Privacy-preserving storage of vaccination data using hashes and zero-knowledge proofs  
🌍 Seamless international verification for travel, work, or events  
🏥 Issuer registration for authorized healthcare providers  
👤 User-controlled identities to prevent data silos  
📈 Immutable audit trails for pandemic response and compliance  
🚫 Fraud detection through duplicate prevention and revocation checks  
🔄 Interoperability with global standards (e.g., WHO-compatible formats)  
✅ Instant verification without revealing sensitive details  

## 🛠 How It Works
This project leverages 8 Clarity smart contracts to handle identity, issuance, verification, and governance in a decentralized manner. Users (individuals), issuers (clinics/doctors), and verifiers (airports/governments) interact via a simple dApp interface.

**For Users (Travelers/Patients)**  
- Create a decentralized identity (DID) using the IdentityContract.  
- Receive a vaccination credential from an authorized issuer, which is hashed and stored immutably.  
- Share a verifiable presentation (proof) with verifiers without exposing full data.  
- Revoke or update records if needed (e.g., booster shots) via the RecordContract.  

**For Issuers (Healthcare Providers)**  
- Register as an authorized entity using the IssuerRegistryContract.  
- Issue credentials by calling functions in the IssuanceContract, attaching proofs like batch numbers or dates.  
- Sign records with your private key for authenticity.  

**For Verifiers (Border Control/Events)**  
- Query the VerificationContract with a user's proof to confirm validity instantly.  
- Check revocation status via the RevocationContract without accessing raw data.  
- Log verifications for auditing in the AuditContract during outbreaks.  

Boom! Secure, tamper-proof verification in seconds, enabling faster travel and better pandemic management.

## 📂 Smart Contracts
The project is built with 8 interconnected Clarity smart contracts on the Stacks blockchain for modularity, security, and scalability:

1. **IdentityContract.clar**: Manages user DIDs, allowing creation, resolution, and ownership proofs.  
2. **IssuerRegistryContract.clar**: Registers and validates healthcare issuers, preventing unauthorized credential issuance.  
3. **IssuanceContract.clar**: Handles the creation and signing of vaccination credentials by approved issuers.  
4. **RecordContract.clar**: Stores hashed vaccination records with metadata (e.g., vaccine type, date) and supports updates.  
5. **VerificationContract.clar**: Verifies proofs using zero-knowledge methods to confirm record authenticity without data exposure.  
6. **RevocationContract.clar**: Manages credential revocation lists for expired or invalid vaccines.  
7. **AuditContract.clar**: Logs all verifications and issuances for transparent pandemic tracking and compliance.  
8. **GovernanceContract.clar**: Enables community or admin updates to standards, like adding new vaccine types, via multisig voting.  

These contracts interact via traits and cross-calls for efficiency, ensuring the system is robust against single points of failure.