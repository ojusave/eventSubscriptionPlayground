const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const http = require('http');

const app = express();
const PORT = 3000;
const baseURL = "https://ojus.ngrok.dev";
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clientEndpointMap = new Map();

// Middleware
app.use(express.static(path.join(__dirname, '.')));
app.use(bodyParser.json());

let config = {};
let currentAccess_token;

wss.on('connection', (ws, req) => {
    console.log('Client connected');
    const endpointId = req.url.split('/').pop();
    clientEndpointMap.set(ws, endpointId);

    ws.on('close', () => {
        console.log('Client disconnected');
        const disconnectedEndpointId = clientEndpointMap.get(ws);
        console.log(`Endpoint ${disconnectedEndpointId} should be deleted`);
        clientEndpointMap.delete(ws);
    });
});

app.post('/configure-webhook', (req, res) => {
    config = req.body;
    if (req.body.type === 'token') {
        Object.assign(config, {
            type: 'token',
            secretToken: req.body.secretToken,
            clientId: req.body.clientId,
            clientSecret: req.body.clientSecret,
            tokenUrl: req.body.tokenUrl
        });
    }
    const endpointURL = `${baseURL}/webhook-endpoint/${crypto.randomBytes(10).toString('hex')}`;
    console.log('Received Configuration:', config);
    console.log('Generated Endpoint URL:', endpointURL);
    res.json({ endpointURL: endpointURL });
});

app.post('/webhook-endpoint/oauth', webhookOAuth);

app.get('/webhook-endpoint/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'events.html'));
});

app.post('/webhook-endpoint/:id', handleWebhook);

server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

function webhookOAuth(req, res) {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const [clientId, clientSecret] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
        console.log('Incoming Client_Id from Zoom', clientId);
        console.log('Incoming Client_Secret from Zoom:', clientSecret);

        if (clientId === config.clientId && clientSecret === config.clientSecret) {
            const access_token = jwt.sign({ clientId }, clientSecret, { expiresIn: '1h' });
            currentAccess_token = `Bearer ${access_token}`;
            const responseJson = {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": "3599"
            };
            console.log("Incoming request verified. Successfully sent Access Token to Zoom", responseJson);
            return res.status(200).json(responseJson);
        }
    }
    console.log("Zoom Verification Failed");
    return res.status(401).send('Unauthorized');
}


function sendData(req) {
    return {
        method: req.method,
        url: req.url,
        host: req.headers.host,
        date: new Date().toISOString(),
        size: req.headers['content-length'] + " bytes",
        headers: req.headers,
        body: req.body
    };
}
function handleWebhook(req, res) {

    if (req.body.event === 'endpoint.url_validation') {
        const hashForValidate = crypto.createHmac('sha256', config.secretToken)
            .update(req.body.payload.plainToken)
            .digest('hex');
        console.log('Webhook received from Zoom:', req.body);
        console.log('Headers:', req.headers);
        broadcastToWebsocketClients(req.body, req.headers);
        return res.status(200).json({
            plainToken: req.body.payload.plainToken,
            encryptedToken: hashForValidate
        });
    }
    switch (config.type) {
        case 'token':
            tokenAuth(req, res);
            break;
        case 'none':
            defaultHeaders(req, res);
            break;
        case 'basic':
            basicAuth(req, res);
            break;
        case 'custom':
            customHeaderAuth(req, res);
            break;
    }
}

function tokenAuth(req, res) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {

        // Check if the token matches the secretToken from the config
        if (authHeader === currentAccess_token) {
            console.log('Webhook received from Zoom:', req.body);
            console.log('Headers:', req.headers);
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    
                    client.send(JSON.stringify(sendData(req)));
                }
            });
            return res.status(200).send('Webhook received');
        } else {
            console.log('Webhook signature mismatch');
            return res.status(403).send('Signature mismatch');
        }
    } else {
        return res.status(403).send('Missing or incorrect authorization header');
    }

}

function defaultHeaders(req, res) {
    const message = `v0:${req.headers['x-zm-request-timestamp']}:${JSON.stringify(req.body)}`;
    const hashForVerify = crypto.createHmac('sha256', config.secretToken).update(message).digest('hex');
    const signature = `v0=${hashForVerify}`;
    if (req.headers['x-zm-signature'] === signature) {
        console.log('Webhook received from Zoom:', req.body);
        console.log('Headers:', req.headers);
        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                
                client.send(JSON.stringify(sendData(req)));
            }
        });
        return res.status(200).send('Webhook received');
    } else {
        console.log('Webhook signature mismatch');
        return res.status(403).send('Signature mismatch');
    }}

function basicAuth(req, res) {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    if (req.headers.authorization === `Basic ${auth}`) {
        console.log('Webhook received from Zoom with basic auth:', req.body);
        console.log('Headers:', req.headers);
        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                
                client.send(JSON.stringify(sendData(req)));
            }
        });
        return res.status(200).send('Webhook received');
    } else {
        console.log('Basic auth mismatch', req.headers);
        return res.status(403).send('Authorization mismatch');
    }
}

function customHeaderAuth(req, res) {
    if (req.headers[config.customHeader.toLowerCase()] === config.customValue) {
        console.log('Webhook received with custom header:', req.body);

        // Broadcast the webhook event to the WebSocket clients
        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                
                client.send(JSON.stringify(sendData(req)));
            }
        });

        return res.status(200).send('Webhook received');
    } else {
        console.log('Headers:', req.headers)
        return res.status(403).send('Header mismatch');
    }
}

function broadcastToWebsocketClients(data) {
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(data));
        }
    });
}

