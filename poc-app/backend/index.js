'use strict';

const express = require('express');
const _ = require('lodash');

const app = express();
const PORT = process.env.PORT || 3000;
const GO_SERVICE_URL = process.env.GO_SERVICE_URL || 'http://localhost:8080';

// Demo data; lodash is used so the dependency is genuinely referenced.
const SERVICES = [
  { name: 'backend', language: 'node' },
  { name: 'microservice', language: 'go' },
];

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/services', (req, res) => {
  const byLanguage = _.groupBy(SERVICES, 'language');
  res.json({ count: SERVICES.length, byLanguage, goService: GO_SERVICE_URL });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`poc-app backend listening on port ${PORT}`);
});
