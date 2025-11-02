# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(1024), nullable=False)
    modes = db.Column(db.JSON, nullable=False)         # e.g. ["dirs","params"]
    status = db.Column(db.String(64), default='queued')
    progress = db.Column(db.Integer, default=0)
    verdict = db.Column(db.String(64), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    custom_wordlist = db.Column(db.JSON, nullable=True)
    custom_payloads = db.Column(db.JSON, nullable=True)
    params = db.Column(db.JSON, nullable=True)

    results = db.relationship('Result', backref='scan', cascade='all, delete-orphan', lazy=True)

class Result(db.Model):
    __tablename__ = 'results'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    rtype = db.Column(db.String(64))         # directory, parameter, vhost, subdomain, etc
    url = db.Column(db.String(2048))
    param = db.Column(db.String(256))
    payload = db.Column(db.String(1024))
    status_code = db.Column(db.Integer)
    reason = db.Column(db.String(512))
    flags = db.Column(db.JSON, nullable=True)  # list of strings
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Wordlist(db.Model):
    __tablename__ = 'wordlists'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    entries = db.Column(db.Text, nullable=False)  # raw newline separated
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PayloadList(db.Model):
    __tablename__ = 'payloadlists'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    entries = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
