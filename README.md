# CVE Engine V2 🔍🛡️

## Overview

CVE Engine V2 is an advanced vulnerability research and tracking platform designed to provide comprehensive insights into Common Vulnerabilities and Exposures (CVEs). This powerful tool aggregates, analyzes, and presents critical security vulnerability information from multiple authoritative sources.

## 🌟 Key Features

- **Comprehensive CVE Aggregation**
  - Collect vulnerability data from multiple sources including MITRE, NVD, and other security databases
  - Real-time updates and synchronization of vulnerability information

- **Advanced Filtering and Search**
  - Sophisticated search capabilities across CVE metadata
  - Advanced filtering by severity, date, product, and impact

- **Intelligent Vulnerability Analysis**
  - Automated risk scoring and prioritization
  - Detailed vulnerability context and potential mitigation strategies

- **Multi-Source Intelligence**
  - Cross-reference vulnerabilities across different security platforms
  - Provide holistic view of security landscape

## 🛠 Technology Stack

- **Backend:** 
  - Node.js
  - Express.js
  - MongoDB
  - Python (for data processing)

- **Frontend:**
  - React
  - Next.js
  - Tailwind CSS

- **Data Sources:**
  - MITRE CVE Database
  - National Vulnerability Database (NVD)
  - Additional security intelligence platforms

## 📦 Prerequisites

- Node.js (v18+ recommended)
- MongoDB (v5+ recommended)
- Python (v3.8+)
- npm or yarn

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/ManavStud/CVE-Engine-V2.git
cd CVE-Engine-V2
```

### 2. Install Dependencies
```bash
# Install backend dependencies
cd backend
npm install

# Install frontend dependencies
cd ../frontend
npm install
```

### 3. Configure Environment Variables
Create a `.env` file in the `backend` directory with the following variables:
```env
MONGODB_URI=mongodb://localhost:27017/cve_engine
MITRE_REPO_URL=https://github.com/CVEProject/cvelist
JWT_SECRET_KEY=my_dummy_secret_key
JWT_TOKEN_HEADER_KEY=x-auth-token
PORT=3001
EMAIL_USER=your@gmail.com
EMAIL_PASS=your_password
```

### 4. Run the Application
```bash
# Start backend server
cd backend
npm start

# Start frontend development server
cd ../frontend
npm run dev
```

## 🔐 API Endpoints

### Authentication
- `POST /api/auth/login` - User authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/reset-password` - Password reset

### CVE Management
- `GET /api/cve` - List vulnerabilities
- `GET /api/cve/:id` - Get specific CVE details
- `GET /api/cve/search` - Advanced vulnerability search
- `GET /api/cve/stats` - Vulnerability statistics

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines
- Follow existing code style
- Write comprehensive tests
- Update documentation
- Ensure CI/CD checks pass

## 🛡️ Security

If you discover a security vulnerability, please send an email to `cve@deepcytes.io`. We appreciate responsible disclosure.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.


---

**Disclaimer:** This tool is for educational and research purposes. Always follow responsible disclosure practices and obtain proper authorization before scanning or analyzing systems.
