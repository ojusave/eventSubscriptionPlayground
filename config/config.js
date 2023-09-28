// Core Node.js modules
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { access } = require('fs');

// Third-party libraries
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const redis = require('ioredis');
const WebSocket = require('ws');

// App configuration
const app = express();
const PORT = process.env.PORT || 3000;
const baseURL = "https://ojus.ngrok.dev";
const server = http.createServer(app);



module.exports = {
    app,
    server,
    PORT,
    baseURL,
    cors,
    express,
    path,
    redis,
    crypto,
    session,
    axios,
    jwt,
    WebSocket,
    access
};
