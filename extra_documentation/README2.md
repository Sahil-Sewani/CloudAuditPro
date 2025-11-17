# CloudAuditPro

_AWS Security & Compliance dashboard with multi-account scans, S3 checks, and email reports._

- **Frontend:** React + Vite + Tailwind, hosted on **S3 + CloudFront**
- **Backend:** FastAPI on **EC2**, talks to AWS Security Hub & S3 via STS
- **Auth:** Email + password, JWT-based sessions, SES-powered password reset
- **Demo domains (example):**
  - App: `https://app.cloudauditpro.app`
  - API: `https://api.cloudauditpro.app`

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Local Development](#local-development)
  - [Backend Setup](#backend-setup)
  - [Frontend Setup](#frontend-setup)
- [Environment Variables](#environment-variables)
  - [Backend](#backend-env)
  - [Frontend](#frontend-env)
- [Authentication Flow](#authentication-flow)
- [AWS Onboarding / Scans](#aws-onboarding--scans)
- [Email & Password Reset](#email--password-reset)
- [Deployment](#deployment)
  - [Backend on EC2](#backend-on-ec2)
  - [Frontend on S3 + CloudFront](#frontend-on-s3--cloudfront)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

CloudAuditPro is a lightweight SaaS-style application that automatically scans AWS accounts for security misconfigurations using **AWS Security Hub**, then delivers clear, actionable weekly reports via **email or Slack**.  

It’s designed to give teams **instant visibility** into their AWS security posture — without requiring deep AWS expertise or console access.

You deploy a lightweight read-only IAM role in each target account, then CloudAuditPro:

- Assumes that role via **STS**
- Queries **AWS Security Hub** and **S3**
- Summarizes findings (and S3 security posture) in a clean UI
- Optionally emails a text report via **SES**

The app is designed to be simple enough for a single engineer to run, while still following decent architecture patterns (separation of frontend/backend, JWT auth, etc.).

---

## Features

- 🔐 **User auth & JWT sessions**
  - Email/password signup + login
  - Password reset via email (SES)
- 🧾 **Onboarding form**
  - Store AWS Account ID + IAM Role name + region per user
- 🛡 **Security Hub scanning**
  - AssumeRole into target account
  - Pull Security Hub findings over a configured time window
  - Summarize count + human-readable breakdown
- 🪣 **S3 security summary**
  - List buckets
  - Mark which are public / private
  - Mark which have encryption enabled
- 📧 **Email reports**
  - Combine Security Hub summary + S3 summary
  - Send text report via SES to configured recipient
- 🌐 **Modern frontend**
  - React + Vite + Tailwind UI
  - SPA routing for login, signup, forgot password, reset password
- ☁️ **Cloud-native deployment**
  - Backend on EC2
  - Frontend on S3 + CloudFront + ACM
  - SPA-friendly CloudFront error/page handling

---

## Architecture

Very high level:

```text
User Browser
   |
   |  HTTPS
   v
CloudFront (app.cloudauditpro.app)
   |
   v
S3 Bucket (React build: index.html + assets)

Frontend (React) ---> API calls ---> FastAPI backend (EC2: api.cloudauditpro.app)
                                          |
                                          | STS: AssumeRole
                                          v
                                 Customer AWS Account
                                  - CloudAuditProReadRole
                                  - SecurityHubReadOnlyAccess
                                  - AmazonS3ReadOnlyAccess

Backend also uses:
- SES (password reset + reports)
- SQLite (users, connections, reset tokens)
- JWT for auth
