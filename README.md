# ZeroTrustOps

## Zero-Trust Server Access Platform

ZeroTrustOps is a cybersecurity-focused server access platform built around Zero Trust principles such as identity verification, RBAC, risk-aware access decisions, Just-In-Time (JIT) SSH access, temporary authorization, audit logging, session tracking, and access revocation.

## Current Features

- FastAPI backend
- PostgreSQL database
- SQLAlchemy ORM
- Alembic migrations
- JWT authentication
- Argon2 password hashing
- Role-Based Access Control (RBAC)
- Server management
- Access request workflow
- Risk scoring engine
- Policy engine
- SSH public-key management
- JIT SSH access
- JIT access revocation
- Automatic JIT expiration
- Audit logging
- Session management API
- Ubuntu Server + Kali Linux security lab

## Architecture

```text
User
  ↓
Authentication
  ↓
JWT
  ↓
RBAC
  ↓
Access Request
  ↓
Risk Engine
  ↓
Policy Engine
  ↓
Approval
  ↓
JIT SSH Access
  ↓
Session Monitoring
  ↓
Expiration / Revocation
  ↓
Audit Logging
