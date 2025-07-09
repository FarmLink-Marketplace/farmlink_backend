# Project Overview
Farmlink is an agric e-commerce platform that connects Nigerian farmers and other entrepreneurs directly with consumers, removing middlemen to ensure fair pricing and fresh produce. The platform enables farmers to sell efficiently, while consumers enjoy affordable, traceable and quality food with seamless delivery across urban and peri-urban areas.

## Goals & Objective
- Empower farmers to sell produce at fair prices.
- Provide consumers with affordable, fresh farm produce.
- Increase transparency in food sourcing and delivery.
- Build a sustainable and scalable agric - commerce model in Nigeria.
- Support implementation of cold storage and transport solutions.
- Quick links surplus produce to buyers or donation programs to prevent spoilage.

## Target Audience
- Primary Users : Local farmers (Small to mid scale), Urban & Peri-Urban consumers.
- Secondary Users: Logistics Partners, Agri-entrepreneurs, NGOs or Cooperatives.

## Tech Stack

### Backend
- Django Rest Framework (DRF)
- PostgreSQL (using Neon)
- Hosted on Render

### Frontend
- ReactJS (hosted in a separate repo)

### Integrations
- NIMC Verification Service API for ID verification
- Cloudinary (or AWS S3) for image storage
- resend for email service
- Paystack / Flutterwave for payments
- Google Maps API for location

## API Documentation
Access the API docs at: [](#)

## Getting Started (Local Setup)

1. Clone the repository:
```bash
git clone https://github.com/your-org/farmlink-backend.git
cd farmlink-backend 
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  or venv\Scripts\activate on Windows
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Setup .env file with required environment variables
```bash
DEBUG=True
SECRET_KEY=your_secret_key
DATABASE_URL=your_postgres_url
...
```

5. Run migrations and start the server
```bash
python manage.py migrate
python manage.py runserver
```

