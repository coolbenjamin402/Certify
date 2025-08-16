# 🎓 Certify - Blockchain Academic Credentials

Certify is a decentralized application for issuing and verifying academic credentials on the Stacks blockchain.

## 🌟 Features

- ✅ Issue immutable academic certificates
- 🏛️ Register educational institutions
- 🔍 Verify certificates
- 📚 Track student credentials
- ⚠️ Revoke certificates if needed

## 🚀 Getting Started

### Prerequisites

- Clarinet
- Stacks wallet

### 📋 Contract Functions

1. **Register Institution**
```clarity
(contract-call? .certify register-institution "University Name")
```

2. **Issue Certificate**
```clarity
(contract-call? .certify issue-certificate "STUDENT123" "Computer Science 101" "A+")
```

3. **Verify Certificate**
```clarity
(contract-call? .certify get-certificate u1)
```

4. **Get Student Certificates**
```clarity
(contract-call? .certify get-student-certificates "STUDENT123")
```

5. **Revoke Certificate**
```clarity
(contract-call? .certify revoke-certificate u1)
```

## 🔐 Security

- Only registered institutions can issue certificates
- Certificates are immutable once issued
- Only the issuing institution can revoke certificates

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📜 License

MIT
```

